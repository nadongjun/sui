// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use anyhow::Result;
use async_recursion::async_recursion;
use async_trait::async_trait;
use move_binary_format::{
    access::ModuleAccess, binary_views::BinaryIndexedView, file_format::SignatureToken,
    file_format_common::VERSION_MAX,
};
use move_command_line_common::{
    address::{NumericalAddress, ParsedAddress},
    parser::NumberFormat,
};
use move_core_types::{account_address::AccountAddress, ident_str};
use move_package::BuildConfig;
use serde::Serialize;
use sui_json::is_receiving_argument;
use sui_json_rpc_types::{SuiObjectData, SuiObjectDataOptions, SuiRawData};
use sui_protocol_config::ProtocolConfig;
use sui_sdk::apis::ReadApi;
use sui_types::{
    base_types::ObjectID,
    move_package::MovePackage,
    object::Owner,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    resolve_address,
    transaction::{self as Tx, ObjectArg},
    Identifier, TypeTag, SUI_FRAMEWORK_PACKAGE_ID,
};

use crate::{
    bind,
    client_commands::{compile_package, upgrade_package},
    err, error,
    ptb::ptb_parser::{
        argument::Argument as PTBArg,
        command_token::{CommandToken, ASSIGN, GAS_BUDGET, MOVE_CALL, PICK_GAS_BUDGET},
        errors::{span, PTBError, PTBResult, Span, Spanned},
        parser::ParsedPTBCommand,
        utils::{display_did_you_mean, find_did_you_means},
    },
    sp,
};

use super::utils::to_ordinal_contraction;

/// The gas budget is a list of gas budgets that can be used to set the gas budget for a PTB along
/// with a gas picker that can be used to pick the budget from the list if it is set in a PTB.
/// A PTB may have multiple gas budgets but the gas picker can only be set once.
pub struct GasBudget {
    pub gas_budgets: Vec<Spanned<u64>>,
    pub picker: Vec<Spanned<GasPicker>>,
}

/// Types of gas pickers that can be used to pick a gas budget from a list of gas budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasPicker {
    Max,
    Min,
    Sum,
}

// ===========================================================================
// Object Resolution
// ===========================================================================

/// A resolver is used to resolve arguments to a PTB. Depending on the context, we may resolve
/// object IDs in different ways -- e.g., in a pure context they should be resolved to a pure
/// value, whereas in an object context they should be resolved to the appropriate object argument.
#[async_trait]
trait Resolver<'a>: Send {
    /// Resolve a pure value. This should almost always resolve to a pure value.
    async fn pure<T: Serialize + Send>(
        &mut self,
        builder: &mut PTBBuilder<'a>,
        loc: Span,
        x: T,
    ) -> PTBResult<Tx::Argument> {
        builder.ptb.pure(x).map_err(|e| err!(loc, "{e}"))
    }

    async fn resolve_object_id(
        &mut self,
        builder: &mut PTBBuilder<'a>,
        loc: Span,
        x: ObjectID,
    ) -> PTBResult<Tx::Argument>;
}

/// A resolver that resolves object IDs to object arguments.
/// If `is_receiving` is true, then the object argument will be resolved to a receiving object
/// argument.
/// If `is_mut` is true, then the object argument will be resolved to a mutable object argument.
/// This currently always defaults to `true`, but we will want to make better decisions about this
/// in the future.
struct ToObject {
    is_receiving: bool,
    is_mut: bool,
}

impl Default for ToObject {
    fn default() -> Self {
        Self {
            is_receiving: false,
            is_mut: true,
        }
    }
}

impl ToObject {
    fn new(is_receiving: bool) -> Self {
        Self {
            is_receiving,
            // TODO: Make mutability decision be passed in from calling context.
            // For now we assume all uses of shared objects are mutable.
            is_mut: true,
        }
    }
}

#[async_trait]
impl<'a> Resolver<'a> for ToObject {
    async fn resolve_object_id(
        &mut self,
        builder: &mut PTBBuilder<'a>,
        loc: Span,
        obj_id: ObjectID,
    ) -> PTBResult<Tx::Argument> {
        let obj = builder.get_object(obj_id, loc).await?;
        let owner = obj
            .owner
            .ok_or_else(|| err!(loc, "Unable to get owner info for object {obj_id}"))?;
        let object_ref = obj.object_ref();
        let obj_arg = match owner {
            Owner::AddressOwner(_) if self.is_receiving => ObjectArg::Receiving(object_ref),
            Owner::Immutable | Owner::AddressOwner(_) => ObjectArg::ImmOrOwnedObject(object_ref),
            Owner::Shared {
                initial_shared_version,
            } => ObjectArg::SharedObject {
                id: object_ref.0,
                initial_shared_version,
                mutable: self.is_mut,
            },
            Owner::ObjectOwner(_) => {
                error!(loc, "Tried to use an object-owned object as an argument",)
            }
        };
        builder.ptb.obj(obj_arg).map_err(|e| err!(loc, "{e}"))
    }
}

/// A resolver that resolves object IDs that it encounters to pure PTB values.
struct ToPure;

#[async_trait]
impl<'a> Resolver<'a> for ToPure {
    async fn resolve_object_id(
        &mut self,
        builder: &mut PTBBuilder<'a>,
        loc: Span,
        x: ObjectID,
    ) -> PTBResult<Tx::Argument> {
        builder.ptb.pure(x).map_err(|e| err!(loc, "{e}"))
    }
}

/// A resolver that will not perform any type of resolution. This is useful to see if we've already
/// resolved an argument or not.
struct NoResolution;

#[async_trait]
impl<'a> Resolver<'a> for NoResolution {
    async fn resolve_object_id(
        &mut self,
        _builder: &mut PTBBuilder<'a>,
        loc: Span,
        _x: ObjectID,
    ) -> PTBResult<Tx::Argument> {
        error!(loc, "Don't resolve arguments and that's fine");
    }
}

// ===========================================================================
// PTB Builder and PTB Creation
// ===========================================================================

/// The PTBBuilder struct is the main workhorse that transforms a sequence of `ParsedPTBCommand`s
/// into an actual PTB that can be run. The main things to keep in mind are that this contains:
/// - A way to handle identifiers -- note that we "lazily" resolve identifiers to arguments, so
///   that the first usage of the identifier determines what it is resolved to. If an identifier is
///   used in multiple positions at different resolutions (e.g., in one place as an object argument,
///   and in another as a pure value), this will result in an error. This error can be avoided by
///   creating another identifier for the second usage.
/// - A way to resolve arguments -- this is done by calling `resolve` on a `PTBArg` and passing in
///   appropriate context. The context is used to determine how to resolve the argument -- e.g., if
///   an object ID should be resolved to a pure value or an object argument.
/// - A way to handle gas budgets -- this is done by adding gas budgets to the gas budget list and
///   setting the gas picker. The gas picker is used to determine how to pick a gas budget from the
///   list of gas budgets.
/// - A way to bind the result of a command to an identifier.
pub struct PTBBuilder<'a> {
    pub addresses: BTreeMap<String, AccountAddress>,
    /// A map from identifiers to the file scopes in which they were declared. This is used
    /// for reporting shadowing warnings.
    pub identifiers: BTreeMap<String, Vec<Span>>,
    /// The arguments that we need to resolve. This is a map from identifiers to the argument
    /// values -- they haven't been resolved to a transaction argument yet.
    pub arguments_to_resolve: BTreeMap<String, Spanned<PTBArg>>,
    /// The arguments that we have resolved. This is a map from identifiers to the actual
    /// transaction arguments.
    pub resolved_arguments: BTreeMap<String, Tx::Argument>,
    /// Read API for reading objects from chain. Needed for object resolution.
    pub reader: &'a ReadApi,
    /// The last command that we have added. This is used to support assignment commands.
    pub last_command: Option<Tx::Argument>,
    /// The actual PTB that we are building up.
    pub ptb: ProgrammableTransactionBuilder,
    /// The gas budget for the transaction. Built-up as we go, and then finalized at the end.
    pub gas_budget: GasBudget,
    /// Flag to say if we encountered a preview command.
    pub preview_set: bool,
    /// Flag to say if we encountered a warn_shadows command.
    pub warn_on_shadowing: bool,
    /// The list of errors that we have built up while processing commands. We do not report errors
    /// eagerly but instead wait until we have processed all commands to report any errors.
    pub errors: Vec<PTBError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasBudgetError {
    NoGasBudget,
    NoGasPicker(Vec<Spanned<u64>>),
    MultipleGasPickers(Vec<Spanned<GasPicker>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAccess {
    ResultAccess(u16),
    DottedString(String),
}

impl GasBudget {
    pub fn new() -> Self {
        Self {
            gas_budgets: vec![],
            picker: vec![],
        }
    }

    /// Finalize the gas budget. This will return an error if there are no gas budgets or if the
    /// gas budget is set to 0.
    pub fn finalize(self) -> Result<u64, GasBudgetError> {
        if self.gas_budgets.is_empty() {
            return Err(GasBudgetError::NoGasBudget);
        }

        if self.picker.len() > 1 {
            return Err(GasBudgetError::MultipleGasPickers(self.picker));
        }

        let budget = if self.gas_budgets.len() == 1 {
            self.gas_budgets[0].value
        } else {
            match self.picker.get(0).map(|x| &x.value) {
                Some(GasPicker::Max) => self
                    .gas_budgets
                    .iter()
                    .map(|x| x.value)
                    .max()
                    .unwrap()
                    .clone(),
                Some(GasPicker::Min) => self
                    .gas_budgets
                    .iter()
                    .map(|x| x.value)
                    .min()
                    .unwrap()
                    .clone(),
                Some(GasPicker::Sum) => self.gas_budgets.iter().map(|x| x.value).sum(),
                None => return Err(GasBudgetError::NoGasPicker(self.gas_budgets)),
            }
        };

        Ok(budget)
    }

    pub fn add_gas_budget(&mut self, budget: u64, sp: Span) {
        self.gas_budgets.push(span(sp, budget));
    }

    /// Set the gas picker. This will return an error if the gas picker has already been set.
    pub fn set_gas_picker(&mut self, picker: GasPicker, sp: Span) {
        self.picker.push(span(sp, picker));
    }
}

/// Check if a type tag resolves to a pure value or not.
fn is_pure(t: &TypeTag) -> anyhow::Result<bool> {
    Ok(match t {
        TypeTag::Bool
        | TypeTag::U8
        | TypeTag::U64
        | TypeTag::U128
        | TypeTag::Address
        | TypeTag::U16
        | TypeTag::U32
        | TypeTag::U256 => true,
        TypeTag::Vector(t) => is_pure(t)?,
        TypeTag::Struct(_) => false,
        TypeTag::Signer => anyhow::bail!("'signer' is not a valid type"),
    })
}

impl<'a> PTBBuilder<'a> {
    pub fn new(starting_env: BTreeMap<String, AccountAddress>, reader: &'a ReadApi) -> Self {
        Self {
            addresses: starting_env,
            identifiers: BTreeMap::new(),
            arguments_to_resolve: BTreeMap::new(),
            resolved_arguments: BTreeMap::new(),
            ptb: ProgrammableTransactionBuilder::new(),
            reader,
            last_command: None,
            gas_budget: GasBudget::new(),
            errors: Vec::new(),
            preview_set: false,
            warn_on_shadowing: false,
        }
    }

    /// Declare and identifier. This is used to support shadowing warnings.
    pub fn declare_identifier(&mut self, ident: String, ident_loc: Span) {
        let e = self.identifiers.entry(ident).or_default();
        e.push(ident_loc);
    }

    /// Declare a possible address binding. This is used to support address resolution. If the
    /// `possible_addr` is not an address, then this is a no-op.
    pub fn declare_possible_address_binding(
        &mut self,
        ident: String,
        possible_addr: &Spanned<PTBArg>,
    ) {
        match possible_addr.value {
            PTBArg::Address(addr) => {
                self.addresses.insert(ident.to_string(), addr.into_inner());
            }
            PTBArg::Identifier(ref i) => {
                // We do a one-hop resolution here to see if we can resolve the identifier to an
                // externally-bound address (i.e., one coming in through the initial environment).
                // This will also handle direct aliasing of addresses throughout the ptb.
                // Note that we don't do this recursively so no need to worry about loops/cycles.
                if let Some(addr) = self.addresses.get(i) {
                    self.addresses.insert(ident.to_string(), *addr);
                }
            }
            // If we encounter a dotted string e.g., "foo.0" or "sui.io" or something like that
            // this see if we can find an address for it in the environment and bind to it.
            PTBArg::VariableAccess(ref head, ref fields) => {
                let key = format!(
                    "{}.{}",
                    head.value,
                    fields
                        .into_iter()
                        .map(|f| f.value.clone())
                        .collect::<Vec<_>>()
                        .join(".")
                );
                if let Some(addr) = self.addresses.get(&key) {
                    self.addresses.insert(ident, *addr);
                }
            }
            _ => (),
        }
    }

    /// Finalize a PTB. If there were errors during the construction of the PTB these are returned
    /// now. Otherwise, the PTB is finalized and returned along with the finalized gas budget, and
    /// if the preview flag was set.
    /// If the warn_on_shadowing flag was set, then we will print warnings for any shadowed
    /// variables that we encountered during the building of the PTB.
    pub fn finish(mut self) -> Result<(Tx::ProgrammableTransaction, u64, bool), Vec<PTBError>> {
        if self.warn_on_shadowing {
            for (ident, commands) in self.identifiers.iter() {
                if commands.len() == 1 {
                    continue;
                }

                for (i, command_loc) in commands.iter().enumerate() {
                    // NB: We use the file scope of the command, and _not_ the current file
                    // scope for these errors!
                    if i == 0 {
                        self.errors.push(PTBError::WithSource {
                            message: format!("Variable '{}' first declared here", ident),
                            span: *command_loc,
                            help: None,
                        });
                    } else {
                        self.errors.push(PTBError::WithSource {
                            message: format!(
                                "Variable '{}' used again here (shadowed) for the {} time.",
                                ident, to_ordinal_contraction(i + 1)
                            ),
                            span: *command_loc,
                            help: Some("You can either rename this variable, or do not \
                                       pass the `warn-shadows` flag to ignore these types of errors.".to_string()),
                        });
                    }
                }
            }
        }

        let budget = match self.gas_budget.finalize().map_err(|e| match e {
            GasBudgetError::NoGasBudget => self.errors.push(err!(Span::out_of_band_span(), "No gas budget set for transaction")),
            GasBudgetError::NoGasPicker(budgets) => {
                for (i, sp!(bsp, _)) in budgets.into_iter().enumerate() {
                    let err_msg = if i == 0 {
                        // NB: this could span multiple files, so we use the filescope saved with
                        // the budget.
                        PTBError::WithSource {
                            message: "Multiple gas budgets set for transaction with no gas picker. \
                                Gas budget is set for the first time here.".to_string(),
                            span: bsp,
                            help: Some(format!("You should either remove all but one usage of setting the gas budget, or use the \
                                '{PICK_GAS_BUDGET}' command to handle multiple gas budgets")),
                        }
                    } else {
                        PTBError::WithSource {
                            message: format!("Gas budget is set for the {} time here.", to_ordinal_contraction(i + 1)),
                            span: bsp,
                            help: None,
                        }
                    };
                self.errors.push(err_msg);
                }
            }
            GasBudgetError::MultipleGasPickers(pickers) => {
                for (i, sp!(bsp, _)) in pickers.into_iter().enumerate() {
                    let err_msg = if i == 0 {
                        // NB: this could span multiple files, so we use the filescope saved with
                        // the picker.
                        PTBError::WithSource {
                            message: "Multiple gas pickers set for transaction. \
                                First usage of the 'gas-picker' command here.".to_string(),
                            span: bsp,
                            help: Some(format!("You should either remove all but one usage of '{PICK_GAS_BUDGET}'.")),
                        }
                    } else {
                        PTBError::WithSource {
                            message: format!("'{PICK_GAS_BUDGET}' used here for the {} time.", to_ordinal_contraction(i + 1)),
                            span: bsp,
                            help: None,
                        }
                    };
                self.errors.push(err_msg);
                }
            },
        }) {
            Ok(b) => b,
            Err(_) => {
                return Err(self.errors);
            }
        };

        if self.errors.len() > 0 {
            return Err(self.errors);
        }

        let ptb = self.ptb.finish();
        Ok((ptb, budget, self.preview_set))
    }

    /// Resolve an object ID to a Move package.
    async fn resolve_to_package(
        &mut self,
        package_id: ObjectID,
        loc: Span,
    ) -> PTBResult<MovePackage> {
        let object = self
            .reader
            .get_object_with_options(package_id, SuiObjectDataOptions::bcs_lossless())
            .await
            .map_err(|e| err!(loc, "{e}"))?
            .into_object()
            .map_err(|e| err!(loc, "{e}"))?;
        let Some(SuiRawData::Package(package)) = object.bcs else {
            error!(
                loc,
                "BCS field in object '{}' is missing or not a package.", package_id
            );
        };
        let package: MovePackage = MovePackage::new(
            package.id,
            object.version,
            package.module_map,
            ProtocolConfig::get_for_min_version().max_move_package_size(),
            package.type_origin_table,
            package.linkage_table,
        )
        .map_err(|e| err!(loc, "{e}"))?;
        Ok(package)
    }

    /// Resolves the argument to the move call based on the type information of the function being
    /// called.
    async fn resolve_move_call_arg(
        &mut self,
        view: &BinaryIndexedView<'_>,
        ty_args: &[TypeTag],
        sp!(loc, arg): Spanned<PTBArg>,
        param: &SignatureToken,
    ) -> PTBResult<Tx::Argument> {
        // See if we've already resolved this argument or if it's an unambiguously pure value
        if let Ok(res) = self.resolve(span(loc, arg.clone()), NoResolution).await {
            return Ok(res);
        }

        // Otherwise it'a ambiguous what the value should be, and we need to turn to the signature
        // to determine it.
        let mut is_object_arg = false;
        let mut is_receiving = false;

        for tok in param.preorder_traversal() {
            match tok {
                SignatureToken::Struct(..) | SignatureToken::StructInstantiation(..) => {
                    is_object_arg = true;
                    is_receiving |= is_receiving_argument(view, tok);
                    break;
                }
                SignatureToken::TypeParameter(idx) => {
                    let Some(tag) = ty_args.get(*idx as usize) else {
                        error!(loc, "Not enough type parameters supplied for Move call",);
                    };
                    if !is_pure(tag).map_err(|e| err!(loc, "{e}"))? {
                        is_object_arg = true;
                        break;
                    }
                }
                SignatureToken::Bool
                | SignatureToken::U8
                | SignatureToken::U64
                | SignatureToken::U128
                | SignatureToken::Address
                | SignatureToken::Signer
                | SignatureToken::Vector(_)
                | SignatureToken::U16
                | SignatureToken::U32
                | SignatureToken::U256
                | SignatureToken::Reference(_)
                | SignatureToken::MutableReference(_) => {}
            }
        }

        // If the argument is an object argument resolve it to an object argument, otherwise
        // resolve it to a receiving object argument.
        if is_object_arg {
            self.resolve(span(loc, arg), ToObject::new(is_receiving))
                .await
        } else {
            self.resolve(span(loc, arg), ToPure).await
        }
    }

    /// Resolve the arguments to a Move call based on the type information about the function
    /// being called.
    async fn resolve_move_call_args(
        &mut self,
        package: MovePackage,
        sp!(mloc, module_name): &Spanned<Identifier>,
        sp!(floc, function_name): &Spanned<Identifier>,
        ty_args: &[TypeTag],
        args: Vec<Spanned<PTBArg>>,
        package_name_loc: Span,
    ) -> PTBResult<Vec<Tx::Argument>> {
        let module = package
            .deserialize_module(module_name, VERSION_MAX, true)
            .map_err(|e| {
                let help_message = if package.serialized_module_map().is_empty() {
                    Some("No modules found in this package".to_string())
                } else {
                    display_did_you_mean(find_did_you_means(
                        module_name.as_str(),
                        package
                            .serialized_module_map()
                            .iter()
                            .map(|(x, _)| x.as_str()),
                    ))
                };
                let e = err!(*mloc, "{e}");
                if let Some(help_message) = help_message {
                    e.with_help(help_message)
                } else {
                    e
                }
            })?;
        let fdef = module
            .function_defs
            .iter()
            .find(|fdef| {
                module.identifier_at(module.function_handle_at(fdef.function).name)
                    == function_name.as_ident_str()
            })
            .ok_or_else(|| {
                let e = err!(
                    *floc,
                    "Could not resolve function '{}' in module '{}'",
                    function_name,
                    module_name
                );
                if let Some(help_message) = display_did_you_mean(find_did_you_means(
                    function_name.as_str(),
                    module.function_defs.iter().map(|fdef| {
                        module
                            .identifier_at(module.function_handle_at(fdef.function).name)
                            .as_str()
                    }),
                )) {
                    e.with_help(help_message)
                } else {
                    e
                }
            })?;
        let function_signature = module.function_handle_at(fdef.function);
        let parameters = &module.signature_at(function_signature.parameters).0;
        let view = BinaryIndexedView::Module(&module);

        if parameters.len() != args.len() {
            let loc = if args.is_empty() {
                package_name_loc.union_with([*mloc, *floc])
            } else {
                args[0].span.union_with(args[1..].iter().map(|x| x.span))
            };
            error!(
                loc,
                "Expected {} arguments, but got {}",
                parameters.len(),
                args.len()
            );
        }

        let mut call_args = vec![];
        for (param, arg) in parameters.iter().zip(args.into_iter()) {
            let call_arg = self
                .resolve_move_call_arg(&view, ty_args, arg, param)
                .await?;
            call_args.push(call_arg);
        }
        Ok(call_args)
    }

    fn resolve_variable_access(
        &self,
        head: &Spanned<String>,
        fields: Vec<Spanned<String>>,
    ) -> Spanned<ResolvedAccess> {
        if fields.len() == 1 {
            let sp!(field_loc, field) = &fields[0];
            if let Ok(n) = field.parse::<u16>() {
                return span(*field_loc, ResolvedAccess::ResultAccess(n));
            }
        }
        let tl_loc = head.span.union_with(fields.iter().map(|x| x.span));
        span(
            tl_loc,
            ResolvedAccess::DottedString(format!(
                "{}.{}",
                head.value,
                fields
                    .into_iter()
                    .map(|f| f.value)
                    .collect::<Vec<_>>()
                    .join(".")
            )),
        )
    }

    /// Resolve an argument based on the argument value, and the `resolver` that is passed in.
    #[async_recursion]
    async fn resolve(
        &mut self,
        sp!(arg_loc, arg): Spanned<PTBArg>,
        mut ctx: impl Resolver<'a> + 'async_recursion,
    ) -> PTBResult<Tx::Argument> {
        match arg {
            PTBArg::Gas => Ok(Tx::Argument::GasCoin),
            // NB: the ordering of these lines is important so that shadowing is properly
            // supported.
            PTBArg::Identifier(i) if self.arguments_to_resolve.contains_key(&i) => {
                let arg = self.arguments_to_resolve[&i].clone();
                let resolved = self.resolve(arg, ctx).await?;
                self.arguments_to_resolve.remove(&i);
                self.resolved_arguments.insert(i, resolved.clone());
                Ok(resolved)
            }
            PTBArg::Identifier(i) if self.resolved_arguments.contains_key(&i) => {
                Ok(self.resolved_arguments[&i].clone())
            }
            PTBArg::Identifier(i) if self.addresses.contains_key(&i) => {
                // We now have a location for this address (which may have come from the keystore
                // so we didnt' have an address for it before), so we tag it with its first usage
                // location put it in the arguments to resolve and resolve away.
                let addr = self.addresses[&i];
                self.arguments_to_resolve.insert(
                    i.clone(),
                    span(
                        arg_loc,
                        PTBArg::Address(NumericalAddress::new(
                            addr.into_bytes(),
                            NumberFormat::Hex,
                        )),
                    ),
                );
                self.resolve(span(arg_loc, PTBArg::Identifier(i)), ctx)
                    .await
            }
            PTBArg::Bool(b) => ctx.pure(self, arg_loc, b).await,
            PTBArg::U8(u) => ctx.pure(self, arg_loc, u).await,
            PTBArg::U16(u) => ctx.pure(self, arg_loc, u).await,
            PTBArg::U32(u) => ctx.pure(self, arg_loc, u).await,
            PTBArg::U64(u) => ctx.pure(self, arg_loc, u).await,
            PTBArg::U128(u) => ctx.pure(self, arg_loc, u).await,
            PTBArg::U256(u) => ctx.pure(self, arg_loc, u).await,
            PTBArg::String(s) => ctx.pure(self, arg_loc, s).await,
            x @ PTBArg::Option(_) => {
                ctx.pure(
                    self,
                    arg_loc,
                    x.into_move_value_opt().map_err(|e| err!(arg_loc, "{e}"))?,
                )
                .await
            }
            x @ PTBArg::Vector(_) => {
                ctx.pure(
                    self,
                    arg_loc,
                    x.into_move_value_opt().map_err(|e| err!(arg_loc, "{e}"))?,
                )
                .await
            }
            PTBArg::Address(addr) => {
                let object_id = ObjectID::from_address(addr.into_inner());
                ctx.resolve_object_id(self, arg_loc, object_id).await
            }
            PTBArg::VariableAccess(head, fields) => {
                match self.resolve_variable_access(&head, fields) {
                    sp!(l, ResolvedAccess::DottedString(string)) => {
                        self.resolve(span(l, PTBArg::Identifier(string)), ctx).await
                    }
                    sp!(_, ResolvedAccess::ResultAccess(access)) => match self
                        .resolved_arguments
                        .get(&head.value)
                    {
                        Some(Tx::Argument::Result(u)) => Ok(Tx::Argument::NestedResult(*u, access)),
                        Some(
                            x @ (Tx::Argument::NestedResult(..)
                            | Tx::Argument::Input(..)
                            | Tx::Argument::GasCoin),
                        ) => {
                            error!(
                                arg_loc,
                                "Tried to access a nested result, input, or gascoin {}: {}",
                                head.value,
                                x,
                            );
                        }
                        None => {
                            error!(
                                arg_loc,
                                "Tried to access an unresolved identifier: {}", head.value
                            );
                        }
                    },
                }
            }
            PTBArg::Identifier(i) => {
                let did_you_means = find_did_you_means(
                    &i,
                    self.resolved_arguments
                        .keys()
                        .chain(self.arguments_to_resolve.keys())
                        .chain(self.addresses.keys())
                        .map(|x| x.as_str()),
                );
                match display_did_you_mean(did_you_means) {
                    Some(similars) => {
                        error!(arg_loc => help: { "{}", similars }, "Unresolved identifier: '{}'", i)
                    }
                    None => error!(arg_loc, "Unresolved identifier: '{}'", i),
                }
            }
            PTBArg::Array(arr) => {
                let combined = arg_loc.union_with(arr.iter().map(|x| x.span));
                error!(
                    combined,
                    "Tried to resolve an array to a value. \
                       This is invalid and means that you nested an array inside \
                       a pure PTB value (or inside another array)"
                );
            }
            PTBArg::ModuleAccess { .. } => {
                error!(
                    arg_loc => help: {
                        "This is invalid and most likely means that you nested a function call inside \
                        a value (e.g., inside an array, vector, or option)."
                    },
                    "Tried to resolve a module access to a value.",
                );
            }
            PTBArg::TyArgs(..) => {
                error!(
                    arg_loc => help: {
                        "This is invalid and most likely means that you have \
                        your arguments to the command in an incorrect order."
                    },
                    "Tried to resolve a type arguments to a value."
                );
            }
        }
    }

    /// Fetch the `SuiObjectData` for an object ID -- this is used for object resolution.
    async fn get_object(&self, object_id: ObjectID, obj_loc: Span) -> PTBResult<SuiObjectData> {
        let res = self
            .reader
            .get_object_with_options(
                object_id,
                SuiObjectDataOptions::new().with_type().with_owner(),
            )
            .await
            .map_err(|e| err!(obj_loc, "{e}"))?
            .into_object()
            .map_err(|e| err!(obj_loc, "{e}"))?;
        Ok(res)
    }

    /// Add a single PTB command to the PTB that we are building up.
    /// Errors are added to the `errors` field of the PTBBuilder.
    pub async fn handle_command(&mut self, command: ParsedPTBCommand) {
        if let Err(e) = self.handle_command_(command).await {
            self.errors.push(e);
        }
    }

    /// Add a single PTB command to the PTB that we are building up. This is the workhorse of it
    /// all.
    async fn handle_command_(&mut self, mut command: ParsedPTBCommand) -> PTBResult<()> {
        let sp!(cmd_span, tok) = &command.name;
        match tok {
            CommandToken::TransferObjects => {
                assert!(command.args.len() == 2);
                bind!(
                    _,
                    PTBArg::Array(obj_args) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected array of objects");
                    }
                );
                let to_address = command.args.pop().unwrap();
                let to_arg = self.resolve(to_address, ToPure).await?;
                let mut transfer_args = vec![];
                for o in obj_args.into_iter() {
                    let arg = self.resolve(o, ToObject::default()).await?;
                    transfer_args.push(arg);
                }
                self.last_command = Some(
                    self.ptb
                        .command(Tx::Command::TransferObjects(transfer_args, to_arg)),
                );
            }
            CommandToken::Assign if command.args.len() == 1 => {
                bind!(
                    ident_loc,
                    PTBArg::Identifier(i) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected identifier",);
                    }
                );
                let Some(prev_ptb_arg) = self.last_command.take() else {
                    error!(
                        ident_loc => help: {
                           "This is most likely because the previous command did not \
                           produce a result. E.g., '{ASSIGN}' or '{GAS_BUDGET}' commands do not produce results."

                        },
                        "Cannot assign a value to this variable."
                    );
                };
                self.declare_identifier(i.clone(), ident_loc);
                self.resolved_arguments.insert(i, prev_ptb_arg);
            }
            CommandToken::Assign if command.args.len() == 2 => {
                let arg_w_loc = command.args.pop().unwrap();
                bind!(
                    ident_loc,
                    PTBArg::Identifier(i) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected identifier");
                    }
                );
                self.declare_identifier(i.clone(), ident_loc);
                self.declare_possible_address_binding(i.clone(), &arg_w_loc);
                self.arguments_to_resolve.insert(i, arg_w_loc);
            }
            CommandToken::Assign => {
                error!(*cmd_span, "expected 1 or 2 arguments for assignment",)
            }
            CommandToken::MakeMoveVec => {
                bind!(
                    _,
                    PTBArg::Array(args) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected array of argument",);
                    }
                );
                bind!(
                    ty_locs,
                    PTBArg::TyArgs(ty_args) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected type argument",);
                    }
                );
                if ty_args.len() != 1 {
                    error!(ty_locs, "expected 1 type argumen",);
                }
                let ty_arg = ty_args[0]
                    .clone()
                    .into_type_tag(&resolve_address)
                    .map_err(|e| err!(ty_locs, "{e}"))?;
                let mut vec_args: Vec<Tx::Argument> = vec![];
                if is_pure(&ty_arg).map_err(|e| err!(ty_locs, "{e}"))? {
                    for arg in args.into_iter() {
                        let arg = self.resolve(arg, ToPure).await?;
                        vec_args.push(arg);
                    }
                } else {
                    for arg in args.into_iter() {
                        let arg = self.resolve(arg, ToObject::default()).await?;
                        vec_args.push(arg);
                    }
                }
                let res = self
                    .ptb
                    .command(Tx::Command::MakeMoveVec(Some(ty_arg), vec_args));
                self.last_command = Some(res);
            }
            CommandToken::SplitCoins => {
                if command.args.len() != 2 {
                    error!(*cmd_span, "expected 2 argument",);
                }

                bind!(
                    _,
                    PTBArg::Array(amounts) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected array of amount",);
                    }
                );

                let pre_coin = command.args.pop().unwrap();

                let coin = self.resolve(pre_coin, ToObject::default()).await?;
                let mut args = vec![];
                for arg in amounts.into_iter() {
                    let arg = self.resolve(arg, ToPure).await?;
                    args.push(arg);
                }
                let res = self
                    .ptb
                    .command(Tx::Command::SplitCoins(coin.clone(), args));
                self.last_command = Some(res);
            }
            CommandToken::MergeCoins => {
                if command.args.len() != 2 {
                    error!(*cmd_span, "expected 2 argument",);
                }

                bind!(
                    _,
                    PTBArg::Array(coins) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected array of coin",);
                    }
                );

                let pre_coin = command.args.pop().unwrap();

                let coin = self.resolve(pre_coin, ToObject::default()).await?;
                let mut args = vec![];
                for arg in coins.into_iter() {
                    let arg = self.resolve(arg, ToObject::default()).await?;
                    args.push(arg);
                }
                let res = self
                    .ptb
                    .command(Tx::Command::MergeCoins(coin.clone(), args));
                self.last_command = Some(res);
            }
            CommandToken::PickGasBudget => {
                bind!(
                    ident_loc,
                    PTBArg::Identifier(i) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected identifier",);
                    }
                );
                let picker = match i.to_string().as_str() {
                    "max" => GasPicker::Max,
                    "min" => GasPicker::Min,
                    "sum" => GasPicker::Sum,
                    x => error!(ident_loc, "invalid gas picker: {}", x,),
                };
                self.gas_budget.set_gas_picker(picker, ident_loc);
            }
            CommandToken::GasBudget => {
                bind!(
                    budget_loc,
                    PTBArg::U64(budget) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected gas budget");
                    }
                );
                self.gas_budget.add_gas_budget(budget, budget_loc);
            }
            CommandToken::File => {
                error!(*cmd_span, "File commands should be removed at this point");
            }
            CommandToken::FileStart => {
                assert!(command.args.len() == 1);
                bind!(
                    _fname_loc,
                    PTBArg::String(_) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected file name");
                    }
                );
            }
            CommandToken::FileEnd => {
                assert!(command.args.len() == 1);
                bind!(
                    _fname_loc,
                    PTBArg::String(_) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected file name");
                    }
                );
            }
            CommandToken::MoveCall => {
                if command.args.is_empty() {
                    error!(
                        *cmd_span,
                        "must provide function to call for {MOVE_CALL} command",
                    );
                }
                let mut args = vec![];
                let mut ty_args = vec![];
                bind!(
                    mod_access_loc,
                    PTBArg::ModuleAccess {
                        address,
                        module_name,
                        function_name,
                    } = command.args.remove(0),
                    |loc| {
                        error!(loc, "expected module access");
                    }
                );

                for sp!(arg_loc, arg) in command.args.into_iter() {
                    if let PTBArg::TyArgs(targs) = arg {
                        for t in targs.into_iter() {
                            ty_args.push(
                                t.into_type_tag(&resolve_address)
                                    .map_err(|e| err!(arg_loc, "{e}"))?,
                            )
                        }
                    } else {
                        args.push(span(arg_loc, arg));
                    }
                }
                let resolved_address = address.value.clone().into_account_address(&|s| {
                    self.addresses.get(s).cloned().or_else(|| resolve_address(s))
                }).map_err(|e| {
                    let help_message = if let ParsedAddress::Named(name) = address.value {
                        Some(format!("This is most likely because the named address '{name}' is not in scope. \
                                     You can either bind a variable to the address that you want to use or use the address in the command."))
                    } else {
                        None
                    };
                    let e = err!(address.span, "{e}");

                    if let Some(help_message) = help_message {
                        e.with_help(help_message)
                    } else {
                        e
                    }
                })?;
                let package_id = ObjectID::from_address(resolved_address);
                let package = self.resolve_to_package(package_id, address.span).await?;
                let args = self
                    .resolve_move_call_args(
                        package,
                        &module_name,
                        &function_name,
                        &ty_args,
                        args,
                        mod_access_loc,
                    )
                    .await?;
                let move_call = Tx::ProgrammableMoveCall {
                    package: package_id,
                    module: module_name.value,
                    function: function_name.value,
                    type_arguments: ty_args,
                    arguments: args,
                };
                let res = self.ptb.command(Tx::Command::MoveCall(Box::new(move_call)));
                self.last_command = Some(res);
            }
            CommandToken::Publish => {
                if command.args.len() != 1 {
                    let span =
                        Span::union_spans(command.args.iter().map(|x| x.span)).unwrap_or(*cmd_span);
                    error!(
                        span,
                        "expected 1 argument for publish but got {}",
                        command.args.len()
                    );
                }
                bind!(
                    pkg_loc,
                    PTBArg::String(package_path) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected filepath argument for publish",);
                    }
                );
                let package_path = std::path::PathBuf::from(package_path);
                let (dependencies, compiled_modules, _, _) = compile_package(
                    self.reader,
                    BuildConfig::default(),
                    package_path,
                    false, /* with_unpublished_dependencies */
                    false, /* skip_dependency_verification */
                )
                .await
                .map_err(|e| err!(pkg_loc, "{e}"))?;

                let res = self.ptb.publish_upgradeable(
                    compiled_modules,
                    dependencies.published.into_values().collect(),
                );
                self.last_command = Some(res);
            }
            // Update this command to not do as many things. It should result in a single command.
            CommandToken::Upgrade => {
                if command.args.len() != 2 {
                    let span =
                        Span::union_spans(command.args.iter().map(|x| x.span)).unwrap_or(*cmd_span);
                    error!(
                        span,
                        "expected 2 arguments for upgrade but got {}",
                        command.args.len()
                    );
                }
                let mut arg = command.args.pop().unwrap();
                if let sp!(loc, PTBArg::Identifier(id)) = arg {
                    arg = self
                        .arguments_to_resolve
                        .get(&id)
                        .ok_or_else(|| err!(loc, "Unable to find object ID argument for upgrade",))?
                        .clone();
                }
                bind!(cap_loc, PTBArg::Address(upgrade_cap_id) = arg, |loc| {
                    error!(loc, "expected upgrade cap object ID for upgrade",);
                });
                bind!(
                    path_loc,
                    PTBArg::String(package_path) = command.args.pop().unwrap(),
                    |loc| {
                        error!(loc, "expected filepath argument for publish",);
                    }
                );
                let package_path = std::path::PathBuf::from(package_path);

                // TODO(tzakian): Change upgrade command so it doesn't do all this magic for us
                // behind the scene.
                let upgrade_cap_arg = self
                    .resolve(
                        span(cap_loc, PTBArg::Address(upgrade_cap_id)),
                        ToObject::default(),
                    )
                    .await?;

                let (package_id, compiled_modules, dependencies, package_digest, upgrade_policy) =
                    upgrade_package(
                        self.reader,
                        BuildConfig::default(),
                        package_path,
                        ObjectID::from_address(upgrade_cap_id.into_inner()),
                        false, /* with_unpublished_dependencies */
                        false, /* skip_dependency_verification */
                    )
                    .await
                    .map_err(|e| err!(path_loc, "{e}"))?;

                let upgrade_arg = self
                    .ptb
                    .pure(upgrade_policy)
                    .map_err(|e| err!(*cmd_span, "{e}"))?;
                let digest_arg = self
                    .ptb
                    .pure(package_digest)
                    .map_err(|e| err!(*cmd_span, "{e}"))?;
                let upgrade_ticket =
                    self.ptb
                        .command(Tx::Command::MoveCall(Box::new(Tx::ProgrammableMoveCall {
                            package: SUI_FRAMEWORK_PACKAGE_ID,
                            module: ident_str!("package").to_owned(),
                            function: ident_str!("authorize_upgrade").to_owned(),
                            type_arguments: vec![],
                            arguments: vec![upgrade_cap_arg, upgrade_arg, digest_arg],
                        })));
                let upgrade_receipt = self.ptb.upgrade(
                    package_id,
                    upgrade_ticket,
                    dependencies.published.into_values().collect(),
                    compiled_modules,
                );
                let res =
                    self.ptb
                        .command(Tx::Command::MoveCall(Box::new(Tx::ProgrammableMoveCall {
                            package: SUI_FRAMEWORK_PACKAGE_ID,
                            module: ident_str!("package").to_owned(),
                            function: ident_str!("commit_upgrade").to_owned(),
                            type_arguments: vec![],
                            arguments: vec![upgrade_cap_arg, upgrade_receipt],
                        })));
                self.last_command = Some(res);
            }
            CommandToken::WarnShadows => {
                if command.args.len() == 1 {
                    self.warn_on_shadowing = command.args[0].value == PTBArg::Bool(true);
                } else {
                    let span =
                        Span::union_spans(command.args.iter().map(|x| x.span)).unwrap_or(*cmd_span);
                    error!(span, "expected no arguments for warn shadows");
                }
            }
            CommandToken::Preview => {
                if command.args.len() == 1 {
                    self.preview_set = command.args[0].value == PTBArg::Bool(true);
                } else {
                    let span =
                        Span::union_spans(command.args.iter().map(|x| x.span)).unwrap_or(*cmd_span);
                    error!(span, "expected no arguments for preview");
                }
            }
        }
        Ok(())
    }
}

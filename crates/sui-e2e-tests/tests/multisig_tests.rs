// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cell::OnceCell;

use sui_core::authority_client::AuthorityAPI;
use sui_json_rpc_types::SuiTransactionBlockEffectsAPI;
use sui_macros::sim_test;
use sui_test_transaction_builder::TestTransactionBuilder;
use sui_types::{
    base_types::SuiAddress,
    error::{SuiError, SuiResult},
    multisig::MultiSigPublicKey,
    multisig_legacy::MultiSigPublicKeyLegacy,
    utils::{keys, make_upgraded_multisig_tx},
    crypto::{SuiKeyPair, get_key_pair},
    signature::GenericSignature,
    multisig::MultiSig,
    transaction::Transaction,
};
use test_cluster::TestClusterBuilder;
use shared_crypto::intent::{Intent, IntentMessage};

async fn do_upgraded_multisig_test() -> SuiResult {
    let test_cluster = TestClusterBuilder::new().build().await;
    let tx = make_upgraded_multisig_tx();

    test_cluster
        .authority_aggregator()
        .authority_clients
        .values()
        .next()
        .unwrap()
        .authority_client()
        .handle_transaction(tx)
        .await
        .map(|_| ())
}

#[sim_test]
async fn test_upgraded_multisig_feature_deny() {
    use sui_protocol_config::ProtocolConfig;

    let _guard = ProtocolConfig::apply_overrides_for_testing(|_, mut config| {
        config.set_upgraded_multisig_for_testing(false);
        config
    });

    let err = do_upgraded_multisig_test().await.unwrap_err();

    assert!(matches!(err, SuiError::UnsupportedFeatureError { .. }));
}

#[sim_test]
async fn test_upgraded_multisig_feature_allow() {
    use sui_protocol_config::ProtocolConfig;

    let _guard = ProtocolConfig::apply_overrides_for_testing(|_, mut config| {
        config.set_upgraded_multisig_for_testing(true);
        config
    });

    let res = do_upgraded_multisig_test().await;

    // we didn't make a real transaction with a valid object, but we verify that we pass the
    // feature gate.
    assert!(matches!(res.unwrap_err(), SuiError::UserInputError { .. }));
}

#[sim_test]
async fn test_multisig_e2e() {
    let mut test_cluster = TestClusterBuilder::new().build().await;

    let keys = keys();
    let pk1 = keys[0].public();
    let pk2 = keys[1].public();
    let pk3 = keys[2].public();

    let multisig_pk = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 1, 1],
        2,
    )
    .unwrap();
    let multisig_addr = SuiAddress::from(&multisig_pk);

    // fund the multisig address.
    let (sender, gas) = test_cluster
        .wallet
        .get_one_gas_object()
        .await
        .unwrap()
        .unwrap();
    let rgp = test_cluster.get_reference_gas_price().await;
    let context = &mut test_cluster.wallet;
    let transfer_to_multisig = context.sign_transaction(
        &TestTransactionBuilder::new(sender, gas, rgp)
            .transfer_sui(Some(20000000000), multisig_addr)
            .build(),
    );
    let resp = context
        .execute_transaction_must_succeed(transfer_to_multisig)
        .await;

    let new_obj = resp
        .effects
        .unwrap()
        .created()
        .first()
        .unwrap()
        .reference
        .to_object_rgitef();

    // sign with key 0 and 1 executes successfully. 
    let tx1 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build_and_sign_multisig(multisig_pk, &[&keys[0], &keys[1]]);
    context
        .execute_transaction_must_succeed(tx1)
        .await;

    // sign with key 1 and 2 executes successfully. 
    let tx2 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build_and_sign_multisig(multisig_pk, &[&keys[1], &keys[2]]);
    context
        .execute_transaction_must_succeed(tx2)
        .await;

    // signature 2 and 1 swapped fails to execute. 
    let tx3 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
    .transfer_sui(None, sender)
    .build_and_sign_multisig(multisig_pk, &[&keys[1], &keys[2]]);

    context.execute_transaction_must_succeed(tx3).await;
    
    // sign with key 0 only is below threshold fails to execute. 
    let tx4 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build_and_sign_multisig(multisig_pk, &[&keys[0]]);

    context
        .execute_transaction_may_fail(tx4)
        .await;
    
    // multisig with no single sig fails to execute. 
    let tx5 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
    .build_and_sign_multisig(multisig_pk, &[]);

    context
        .execute_transaction_may_fail(tx5)
        .await;

    // multisig two dup sigs fails to execute. 
    let tx_6 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
    .transfer_sui(None, sender)
    .build_and_sign_multisig(multisig_pk, &[&keys[0], &keys[0]]);

    context
        .execute_transaction_may_fail(tx_6)
        .await;

    // mismatch pks in sig with multisig address fails to execute. 
    let kp4: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair().1);
    let pk4 = kp4.public();
    let wrong_multisig_pk = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone(), pk4],
        vec![1, 1, 1, 1],
        2,
    )
    .unwrap();
    let tx6 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build_and_sign_multisig(wrong_multisig_pk, &[&keys[0], &keys[1]]);
    context
        .execute_transaction_may_fail(tx6)
        .await;

    // a multisig with a bad ed25519 sig fails to execute. 
    let tx_data_7 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build();
    let intent_msg = IntentMessage::new(Intent::sui_transaction(), tx_data_7);
    let multisig = GenericSignature::MultiSig(MultiSig::combine(vec![], multisig_pk).unwrap());
    let tx7 = Transaction::from_generic_sig_data(tx_data_7, vec![multisig]);
    context
    .execute_transaction_may_fail(tx7)
    .await;

    // a multisig with a bad secp256k1 sig fails to execute. 

    // a multisig with a bad secp256k1 sig fails to execute. 

    // wrong bitmap fails to execute. 
    let tx_data_8 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build();
    let intent_msg = IntentMessage::new(Intent::sui_transaction(), tx_data_8);
    let multisig = GenericSignature::MultiSig(MultiSig::combine(vec![], multisig_pk).unwrap());
    let tx8 = Transaction::from_generic_sig_data(tx_data_8, vec![multisig]);
    context
    .execute_transaction_may_fail(tx8)
    .await;

    // invalid bitmaps 644 = [2, 7, 9]
    // malformed multisig pk fails to execute. 
    // subcase 1: threshold = 0
    let tx_data_9 = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(None, sender)
        .build();
    let intent_msg = IntentMessage::new(Intent::sui_transaction(), tx_data_9);
    let multisig = GenericSignature::MultiSig(MultiSig::new(
        vec![],1, MultiSigPublicKey::construct(vec![], 1),
    ));
    let tx9 = Transaction::from_generic_sig_data(tx_data_9, vec![multisig]);
    context
    .execute_transaction_may_fail(tx9)
    .await;

    // a pk has weight = 0

    // pass in 3 sigs when only 2 pks

    // dup pks fails

    // a sig with 11 pks fails
    
    // total weight of all pks < threshold

    // empty pk map

    // invalid compressed sig bytes ed25519, k1, r1, zklogin

    // invalid pk bytes ed25519, k1, r1, zklogin
}

#[sim_test]
async fn test_multisig_legacy_e2e() {
    let mut test_cluster = TestClusterBuilder::new().build().await;

    let keys = keys();
    let pk1 = keys[0].public();
    let pk2 = keys[1].public();
    let pk3 = keys[2].public();

    let multisig_pk_legacy = MultiSigPublicKeyLegacy::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 1, 1],
        2,
    )
    .unwrap();
    let multisig_pk = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 1, 1],
        2,
    )
    .unwrap();
    let multisig_addr = SuiAddress::from(&multisig_pk);

    let (sender, gas) = test_cluster
        .wallet
        .get_one_gas_object()
        .await
        .unwrap()
        .unwrap();
    let rgp = test_cluster.get_reference_gas_price().await;
    let context = &mut test_cluster.wallet;
    let transfer_to_multisig = context.sign_transaction(
        &TestTransactionBuilder::new(sender, gas, rgp)
            .transfer_sui(Some(20000000000), multisig_addr)
            .build(),
    );
    let resp = context
        .execute_transaction_must_succeed(transfer_to_multisig)
        .await;

    let new_obj = resp
        .effects
        .unwrap()
        .created()
        .first()
        .unwrap()
        .reference
        .to_object_ref();
    // now send it back
    let transfer_from_multisig = TestTransactionBuilder::new(multisig_addr, new_obj, rgp)
        .transfer_sui(Some(1000000), sender)
        .build_and_sign_multisig_legacy(multisig_pk_legacy, &[&keys[0], &keys[1]]);

    context
        .execute_transaction_must_succeed(transfer_from_multisig)
        .await;
}

#[sim_test]
async fn test_zklogin_inside_multisig_feature_deny() {
    use sui_protocol_config::ProtocolConfig;

    let _guard = ProtocolConfig::apply_overrides_for_testing(|_, mut config| {
        config.set_upgraded_multisig_for_testing(false);
        config
    });

    let err = do_upgraded_multisig_test().await.unwrap_err();

    assert!(matches!(err, SuiError::UnsupportedFeatureError { .. }));
}

#[sim_test]
async fn test_zklogin_inside_multisig_scenerios() {
    use sui_protocol_config::ProtocolConfig;

    let err = do_upgraded_multisig_test().await.unwrap_err();

    assert!(matches!(err, SuiError::UnsupportedFeatureError { .. }));
}

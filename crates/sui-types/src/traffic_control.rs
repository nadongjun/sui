// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, net::SocketAddr};

use crate::error::{SuiError, SuiResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct TrafficTally {
    pub remote_addr: Option<SocketAddr>,
    pub end_user_addr: Option<SocketAddr>,
    pub result: SuiResult,
    pub timestamp: DateTime<Utc>,
}

// Serializable representation of policy types, used in config
// in order to easily change in tests or to killswitch
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub enum PolicyType {
    /// Does nothing
    #[default]
    NoOp,
    /// Simple policy that blocks IP when any error code in
    /// `tallyable_error_codes` is encountered 3 times in a row
    SimpleErrorTest,
}

// Nonserializable representation, also note that inner types are
// not object safe, so we can't use a trait object instead
#[derive(Clone)]
pub enum TrafficControlPolicyEnum {
    NoOp(NoOpPolicy),
    SimpleErrorTest(SimpleErrorTestPolicy),
}

impl TrafficControlPolicyEnum {
    pub fn handle_error_tally(&mut self, tally: TrafficTally) -> bool {
        match self {
            TrafficControlPolicyEnum::NoOp(policy) => policy.handle_error_tally(tally),
            TrafficControlPolicyEnum::SimpleErrorTest(policy) => policy.handle_error_tally(tally),
        }
    }

    pub fn handle_spam_tally(&mut self, tally: TrafficTally) -> bool {
        match self {
            TrafficControlPolicyEnum::NoOp(policy) => policy.handle_spam_tally(tally),
            TrafficControlPolicyEnum::SimpleErrorTest(policy) => policy.handle_spam_tally(tally),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct PolicyConfig {
    pub tallyable_error_codes: Vec<SuiError>,
    pub remote_blocklist_ttl_sec: u64,
    pub end_user_blocklist_ttl_sec: u64,
    pub policy_type: PolicyType,
    pub channel_capacity: usize,
}

impl PolicyConfig {
    pub fn to_policy(&self) -> TrafficControlPolicyEnum {
        match self.policy_type {
            PolicyType::NoOp => TrafficControlPolicyEnum::NoOp(NoOpPolicy::new(self.clone())),
            PolicyType::SimpleErrorTest => {
                TrafficControlPolicyEnum::SimpleErrorTest(SimpleErrorTestPolicy::new(self.clone()))
            }
        }
    }
}

pub trait TrafficControlPolicy: Clone {
    fn handle_error_tally(&mut self, tally: TrafficTally) -> bool;
    fn handle_spam_tally(&mut self, tally: TrafficTally) -> bool;
    fn policy_config(&self) -> &PolicyConfig;
}

#[derive(Clone)]
pub struct NoOpPolicy {
    config: PolicyConfig,
}

impl NoOpPolicy {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }
}

impl TrafficControlPolicy for NoOpPolicy {
    fn handle_error_tally(&mut self, _tally: TrafficTally) -> bool {
        false
    }

    fn handle_spam_tally(&mut self, _tally: TrafficTally) -> bool {
        false
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

#[derive(Clone)]
pub struct SimpleErrorTestPolicy {
    config: PolicyConfig,
    frequencies: HashMap<SocketAddr, u64>,
}

impl SimpleErrorTestPolicy {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            frequencies: HashMap::new(),
        }
    }
}

impl TrafficControlPolicy for SimpleErrorTestPolicy {
    fn handle_error_tally(&mut self, tally: TrafficTally) -> bool {
        // increment the count for the IP
        let count = self
            .frequencies
            .entry(tally.remote_addr.unwrap())
            .or_insert(0);
        *count += 1;
        *count >= 3
    }

    fn handle_spam_tally(&mut self, _tally: TrafficTally) -> bool {
        false
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

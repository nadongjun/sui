// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use futures::channel::mpsc::TrySendError;
use mysten_metrics::spawn_monitored_task;
use mysten_network::config;
use parking_lot::RwLock;
use serde_with::de;
use sui_types::traffic_control::{
    NoOpPolicy, PolicyConfig, PolicyType, SimpleErrorTestPolicy, TrafficControlPolicy, TrafficTally,
};
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Clone)]
pub struct TrafficController {
    tally_channel: mpsc::Sender<TrafficTally>,
    blocklist: Arc<RwLock<HashMap<SocketAddr, DateTime<Utc>>>>,
    //metrics: TrafficControllerMetrics, // TODO
}

impl TrafficController {
    // TODO(william) combine policy and capacity into a config struct in NodeConfig
    pub async fn spawn(policy_config: PolicyConfig) -> Self {
        let (tx, mut rx) = mpsc::channel(policy_config.channel_capacity);
        let ret = Self {
            tally_channel: tx,
            blocklist: Arc::new(RwLock::new(HashMap::new())),
        };
        spawn_monitored_task!(run_tally_loop(rx, policy_config, ret.blocklist.clone()));
        ret
    }

    pub fn tally(&self, tally: TrafficTally) {
        // Use try_send rather than send mainly to avoid creating backpressure
        // on the caller if the channel is full, which may slow down the critical
        // path. Dropping the tally on the floor should be ok, as in this case
        // we are effectively sampling traffic, which we would need to do anyway
        // if we are overloaded
        match self.tally_channel.try_send(tally) {
            Err(TrySendError::Full(_)) => {
                warn!("TrafficController tally channel full, dropping tally");
                // TODO: metric
            }
            Err(TrySendError::Closed(_)) => {
                panic!("TrafficController tally channel closed unexpectedly");
            }
            Ok(_) => {}
        }
    }

    pub async fn check(
        &self,
        remote_addr: Option<SocketAddr>,
        end_user_addr: Option<SocketAddr>,
    ) -> bool {
        match (remote_addr, end_user_addr) {
            (Some(remote), _) => self.check_and_clear_blocklist(remote).await,
            (_, Some(end_user)) => self.check_and_clear_blocklist(end_user).await,
            _ => true,
        }
    }

    async fn check_and_clear_blocklist(&self, ip: SocketAddr) -> bool {
        let now = Utc::now();
        let expiration = {
            let expiry = self.blocklist.read();
            expiry.get(&ip).map(|expiry| expiry.clone())
        };
        match expiration {
            Some(expiration) if now >= expiration => {
                self.blocklist.write().remove(&ip);
                true
            }
            None => true,
            _ => false,
        }
    }
}

async fn run_tally_loop(
    mut receiver: mpsc::Receiver<TrafficTally>,
    policy_config: PolicyConfig,
    blocklist: Arc<RwLock<HashMap<SocketAddr, DateTime<Utc>>>>,
) {
    let policy = policy_config.to_policy();
    loop {
        tokio::select! {
            received = receiver.recv() => match received {
                Some(tally) => {
                    handle_spam_tally(policy.clone(), tally.clone()).await;
                    if tally.clone().result.is_err() {
                        handle_error_tally(policy.clone(), tally, blocklist).await;
                    }
                }
                None => {
                    panic!("TrafficController tally channel closed unexpectedly");
                },
            }
        }
    }
}

async fn handle_error_tally(
    config: PolicyConfig,
    tally: TrafficTally,
    blocklist: Arc<RwLock<HashMap<SocketAddr, DateTime<Utc>>>>,
) {
    let err = if let Some(err) = tally.clone().result.err() {
        err
    } else {
        return;
    };
    let policy = config.to_policy();
    if config.tallyable_error_codes.contains(&err) && policy.handle_error_tally(tally.clone()) {
        blocklist.write().insert(
            tally.remote_addr.unwrap_or(tally.end_user_addr.unwrap()),
            Utc::now()
                + chrono::Duration::seconds(config.remote_blocklist_ttl_sec.try_into().unwrap()),
        );
    }
}

async fn handle_spam_tally(_policy: PolicyConfig, _tally: TrafficTally) {
    // TODO
}

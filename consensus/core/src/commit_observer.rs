// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub(crate) struct CommitObserver {
    context: Arc<Context>,
    commit_interpreter: Linearizer,
    /// A channel to send committed sub-dags to the consumer of consensus output.
    /// TODO: We will need to figure out a solution to handle back pressure.
    sender: tokio::sync::mpsc::UnboundedSender<CommittedSubDag>,
}

impl CommitObserver {
    pub fn new(
        context: Arc<Context>,
        commit_interpreter: Linearizer,
        sender: tokio::sync::mpsc::UnboundedSender<CommittedSubDag>,
    ) -> Self {
        Self {
            context,
            commit_interpreter,
            sender,
        }
    }
}

use std::future::Future;

use tokio::task::{JoinError, JoinSet};

pub(super) struct NativeConnectionTasks {
    tasks: JoinSet<()>,
}

impl NativeConnectionTasks {
    pub(super) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(super) fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        self.tasks.spawn(task);
    }

    pub(super) async fn join_next(&mut self) {
        if let Some(result) = self.tasks.join_next().await {
            report_connection_task_result(result);
        }
    }

    pub(super) async fn drain(mut self) {
        while let Some(result) = self.tasks.join_next().await {
            report_connection_task_result(result);
        }
    }
}

fn report_connection_task_result(result: Result<(), JoinError>) {
    if let Err(error) = result {
        log::error!(
            target: "fluxheim::native_runtime",
            "native connection task exited unexpectedly while draining: {error}"
        );
    }
}

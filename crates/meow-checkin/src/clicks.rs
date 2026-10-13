//! Click steps wait here for an app to perform them.
//!
//! An app is "attached" while it holds a [`ClickSubscription`] (an open
//! `GET /checkin/clicks` stream). One request is pending at a time; it is
//! sent to every attached app, and handed again to an app that attaches
//! while it is still pending. The first report for the request wins.

use crate::model::{ClickReport, ClickRequest};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, oneshot, watch};

#[derive(Debug, PartialEq, Eq)]
pub enum ClickOutcome {
    Reported(ClickReport),
    /// No app attached (within the wait), or the only one left.
    NoApp,
    /// An app took the request and never answered.
    TimedOut,
}

struct Pending {
    request: ClickRequest,
    answer: oneshot::Sender<ClickReport>,
}

struct Shared {
    pending: Mutex<Option<Pending>>,
    requests: broadcast::Sender<ClickRequest>,
    attached: watch::Sender<usize>,
}

#[derive(Clone)]
pub struct ClickHub(Arc<Shared>);

impl Default for ClickHub {
    fn default() -> Self {
        Self(Arc::new(Shared {
            pending: Mutex::new(None),
            requests: broadcast::channel(16).0,
            attached: watch::channel(0).0,
        }))
    }
}

/// An attached app. Dropping it detaches.
pub struct ClickSubscription {
    shared: Arc<Shared>,
    receiver: broadcast::Receiver<ClickRequest>,
    first: Option<ClickRequest>,
}

impl ClickSubscription {
    /// The next request to perform; `None` when the hub is gone.
    pub async fn next(&mut self) -> Option<ClickRequest> {
        if let Some(first) = self.first.take() {
            return Some(first);
        }
        loop {
            match self.receiver.recv().await {
                Ok(request) => return Some(request),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl Drop for ClickSubscription {
    fn drop(&mut self) {
        self.shared
            .attached
            .send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl ClickHub {
    /// Attaches an app.
    pub fn subscribe(&self) -> ClickSubscription {
        // Under the lock: a request made right now is either seen as
        // pending here or received from the channel, never both or neither.
        let pending = self.0.pending.lock();
        let receiver = self.0.requests.subscribe();
        let first = pending.as_ref().map(|p| p.request.clone());
        self.0.attached.send_modify(|n| *n += 1);
        ClickSubscription {
            shared: Arc::clone(&self.0),
            receiver,
            first,
        }
    }

    pub fn attached(&self) -> usize {
        *self.0.attached.borrow()
    }

    /// Follows the number of attached apps.
    pub fn watch_attached(&self) -> watch::Receiver<usize> {
        self.0.attached.subscribe()
    }

    /// The app's answer for the pending request. `false`: no such request
    /// (already answered, timed out, or never made).
    pub fn report(&self, report: ClickReport) -> bool {
        let mut pending = self.0.pending.lock();
        let matches = pending.as_ref().is_some_and(|p| {
            p.request.id == report.request_id
                && p.request.steps.iter().any(|s| s.id() == report.step_id)
        });
        if !matches {
            return false;
        }
        pending
            .take()
            .is_some_and(|p| p.answer.send(report).is_ok())
    }

    /// Asks the attached apps to perform `request` and waits for the
    /// report. Waits `attach_wait` for an app when none is attached, and
    /// `report_wait` for the report once one is.
    pub async fn request(
        &self,
        request: ClickRequest,
        attach_wait: Duration,
        report_wait: Duration,
    ) -> ClickOutcome {
        let mut attached = self.0.attached.subscribe();
        if *attached.borrow_and_update() == 0 {
            let appeared = tokio::time::timeout(attach_wait, attached.wait_for(|n| *n > 0)).await;
            if !matches!(appeared, Ok(Ok(_))) {
                return ClickOutcome::NoApp;
            }
        }
        let (answer, answered) = oneshot::channel();
        {
            let mut pending = self.0.pending.lock();
            *pending = Some(Pending {
                request: request.clone(),
                answer,
            });
            let _ = self.0.requests.send(request);
        }
        let outcome = tokio::select! {
            report = answered => report.map_or(ClickOutcome::TimedOut, ClickOutcome::Reported),
            () = tokio::time::sleep(report_wait) => ClickOutcome::TimedOut,
            () = Self::all_gone(&mut attached, attach_wait) => ClickOutcome::NoApp,
        };
        *self.0.pending.lock() = None;
        outcome
    }

    /// Completes once no app has been attached for `grace`.
    async fn all_gone(attached: &mut watch::Receiver<usize>, grace: Duration) {
        loop {
            if attached.wait_for(|n| *n == 0).await.is_err() {
                std::future::pending::<()>().await;
            }
            let back = tokio::time::timeout(grace, attached.wait_for(|n| *n > 0)).await;
            if !matches!(back, Ok(Ok(_))) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Access, ClickStep, Step};

    fn request(id: &str) -> ClickRequest {
        ClickRequest {
            id: id.into(),
            task_id: "t1".into(),
            access: Access::Direct,
            policy: None,
            timeout_ms: 20_000,
            steps: vec![Step::Click(ClickStep {
                id: "s2".into(),
                name: "领取".into(),
                page: "https://a.example/user".into(),
                locators: vec![],
                text: String::new(),
                tag: String::new(),
            })],
        }
    }

    fn report(request_id: &str, step_id: &str) -> ClickReport {
        ClickReport {
            request_id: request_id.into(),
            step_id: step_id.into(),
            found: true,
            final_url: None,
            password_field: false,
            error: None,
        }
    }

    const WAIT: Duration = Duration::from_secs(2);
    const REPORT: Duration = Duration::from_secs(50);

    #[tokio::test(start_paused = true)]
    async fn without_an_app_the_answer_is_no_app() {
        let hub = ClickHub::default();
        let start = tokio::time::Instant::now();
        assert_eq!(
            hub.request(request("c1"), WAIT, REPORT).await,
            ClickOutcome::NoApp
        );
        assert_eq!(start.elapsed(), WAIT);
        assert!(!hub.report(report("c1", "s2")));
    }

    #[tokio::test(start_paused = true)]
    async fn an_attached_app_gets_the_request_and_its_report_is_the_answer() {
        let hub = ClickHub::default();
        let mut app = hub.subscribe();
        assert_eq!(hub.attached(), 1);
        let asking = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.request(request("c1"), WAIT, REPORT).await })
        };
        let got = app.next().await.unwrap();
        assert_eq!(got.id, "c1");
        // Reports for something else are not the answer.
        assert!(!hub.report(report("c9", "s2")));
        assert!(!hub.report(report("c1", "other")));
        assert!(hub.report(report("c1", "s2")));
        assert_eq!(
            asking.await.unwrap(),
            ClickOutcome::Reported(report("c1", "s2"))
        );
        // Answered once.
        assert!(!hub.report(report("c1", "s2")));
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_attaching_within_the_wait_gets_the_request() {
        let hub = ClickHub::default();
        let asking = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.request(request("c1"), WAIT, REPORT).await })
        };
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut app = hub.subscribe();
        let got = app.next().await.unwrap();
        assert!(hub.report(report(&got.id, "s2")));
        assert!(matches!(asking.await.unwrap(), ClickOutcome::Reported(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_attaching_while_a_request_is_pending_is_handed_it() {
        let hub = ClickHub::default();
        let first = hub.subscribe();
        let asking = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.request(request("c1"), WAIT, REPORT).await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut second = hub.subscribe();
        assert_eq!(second.next().await.unwrap().id, "c1");
        drop(first);
        assert!(hub.report(report("c1", "s2")));
        assert!(matches!(asking.await.unwrap(), ClickOutcome::Reported(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_that_never_reports_times_the_step_out() {
        let hub = ClickHub::default();
        let _app = hub.subscribe();
        let start = tokio::time::Instant::now();
        assert_eq!(
            hub.request(request("c1"), WAIT, REPORT).await,
            ClickOutcome::TimedOut
        );
        assert_eq!(start.elapsed(), REPORT);
        assert!(!hub.report(report("c1", "s2")));
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_leaving_mid_request_is_no_app() {
        let hub = ClickHub::default();
        let app = hub.subscribe();
        let asking = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.request(request("c1"), WAIT, REPORT).await })
        };
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(app);
        assert_eq!(hub.attached(), 0);
        assert_eq!(asking.await.unwrap(), ClickOutcome::NoApp);
    }
}

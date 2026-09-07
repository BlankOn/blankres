//! The daemon's decision loop: journal entry in, telemetry event out, and — only when the server
//! asks — a pending payload written for the user to review.

use std::path::PathBuf;
use std::time::Duration;

use blankres_client::Client;
use blankres_collect::pkg::PackageBackend;
use blankres_collect::record::CoredumpRecord;
use blankres_collect::stage1::Stage1Collector;
use blankres_collect::stage2::Stage2Collector;
use blankres_collect::sys::Filesystem;
use blankres_collect::Budget;
use blankres_report::event::{CrashEvent, PayloadDirective};
use blankres_report::report::PendingUpload;
use blankres_session::{write_pending, Declined};

use crate::config::ClientConfig;
use crate::journal::now_secs;
use crate::spool::Spool;
use crate::state::State;

/// What happened to one crash, for logging and for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The user has declined this signature, or the executable is over its rate limit.
    Suppressed(String),
    /// Reported; the server did not want a core, and it has been deleted.
    ReportedCoreDropped { signature: String },
    /// Reported; the server asked for a payload, which is now awaiting consent.
    AwaitingConsent { signature: String, path: PathBuf },
    /// Could not reach the server. The event is spooled, and the payload is shown to the user
    /// anyway rather than the crash passing in silence.
    SpooledAwaitingConsent { signature: String, path: PathBuf },
}

pub struct Reporter<F: Filesystem, P: PackageBackend> {
    stage1: Stage1Collector<F, P>,
    stage2: Stage2Collector<F, P>,
    client: Client,
    config: ClientConfig,
    spool: Spool,
}

impl<F: Filesystem + Clone, P: PackageBackend> Reporter<F, P> {
    pub fn new(
        stage1: Stage1Collector<F, P>,
        stage2: Stage2Collector<F, P>,
        client: Client,
        config: ClientConfig,
        spool: Spool,
    ) -> Self {
        Self {
            stage1,
            stage2,
            client,
            config,
            spool,
        }
    }

    /// Handle one coredump.
    ///
    /// Suppression is checked before any collection. Then the stage-1 event and the cheap half of
    /// a stage-2 payload are prepared *concurrently*: the user should never wait on the network to
    /// be told their program crashed, and a server that is slow or down must not turn a crash into
    /// silence. Only the expensive half of stage 2, hashing the mapped libraries, waits until the
    /// payload is known to be worth keeping.
    pub async fn handle_coredump(
        &self,
        record: &CoredumpRecord,
        state: &mut State,
    ) -> std::io::Result<Outcome> {
        let executable = record.executable().unwrap_or("unknown").to_owned();

        // Cheapest possible gate, before any collection at all.
        let limit = self.config.rate_limit_per_hour;
        let seen = state.charge_rate_limit(&executable, now_secs());
        if seen >= limit {
            return Ok(Outcome::Suppressed(format!(
                "{executable} is over its rate limit: {seen} crashes in the last hour, limit \
                 {limit}. Raise rate_limit_per_hour to report more."
            )));
        }

        let mut budget = Budget::stage1();
        // The count is provisional: it is needed to build the event, and the event may yet be
        // suppressed, but an over-count is harmless where an under-count would hide a pattern.
        let signature_hash = {
            let probe = self.stage1.collect_within(record, 0, &mut budget);
            probe.signature.hash
        };

        // The desktop front end runs unprivileged and records "never for this problem" in the
        // user's own directory, so the daemon has to consult that as well as its own state.
        let uid = record.uid().unwrap_or(0);
        if state.is_declined(&signature_hash)
            || Declined::load(&self.config.crash_dir, uid).contains(&signature_hash)
        {
            return Ok(Outcome::Suppressed(format!(
                "the user declined signature {}",
                &signature_hash[..12]
            )));
        }

        let count = state.note_signature(&signature_hash);
        let event = self.stage1.collect_within(record, count, &mut budget);

        tracing::debug!(
            executable = %event.executable,
            signature = %&event.signature.hash[..12],
            elapsed = ?budget.elapsed(),
            "stage 1 collected"
        );

        // Ask the server, on its own task, under a deadline.
        let query = self.ask_server(event.clone());

        // Meanwhile, assemble everything that comes from the journal record. This costs
        // microseconds and means the report is ready the moment the answer arrives, or the moment
        // we give up waiting for one.
        let mut stage2 = Budget::stage2();
        let mut report = self.stage2.collect_without_verification(
            event.clone(),
            String::new(),
            record,
            &mut stage2,
        );

        // A panicking task is indistinguishable from an unreachable server here, and the
        // right response to both is the same.
        let directive = query.await.unwrap_or(None);
        let signature = event.signature.hash.clone();

        match directive {
            // The server answered and does not want a payload. The common case at steady state:
            // reclaim the disk and say nothing, because there is nothing the user could add.
            Some(directive) if !directive.is_actionable(now_secs()) => {
                self.drop_core(record);
                Ok(Outcome::ReportedCoreDropped { signature })
            }

            // The server answered and wants the payload.
            Some(directive) => {
                self.stage2.verify_into(&mut report, record, &mut stage2);
                report.directive_id = directive.id.clone();
                let path = self.write_pending(report, directive, false)?;
                tracing::info!(
                    signature = %&signature[..12],
                    path = %path.display(),
                    "payload requested; awaiting user consent"
                );
                Ok(Outcome::AwaitingConsent { signature, path })
            }

            // No answer. Spool the event for later, and still tell the user: a crash we could not
            // report is not a crash we should hide from the person it happened to. Whether the
            // payload is actually wanted is settled when they choose to send it.
            None => {
                let _ = self.spool.push(&event);
                self.stage2.verify_into(&mut report, record, &mut stage2);
                let path = self.write_pending(report, unconfirmed_directive(), true)?;
                tracing::info!(
                    signature = %&signature[..12],
                    path = %path.display(),
                    "server unreachable; event spooled and the crash shown to the user anyway"
                );
                Ok(Outcome::SpooledAwaitingConsent { signature, path })
            }
        }
    }

    /// Send the stage-1 event on its own task, bounded by a deadline.
    ///
    /// Returning `None` covers every way of not getting an answer, because they all lead to the
    /// same decision: do not leave the user in the dark.
    fn ask_server(&self, event: CrashEvent) -> tokio::task::JoinHandle<Option<PayloadDirective>> {
        let client = self.client.clone();
        let deadline = Duration::from_secs(self.config.directive_timeout_secs.max(1));

        tokio::spawn(async move {
            let request = client.send_events(std::slice::from_ref(&event));
            match tokio::time::timeout(deadline, request).await {
                Ok(Ok(mut directives)) if !directives.is_empty() => Some(directives.remove(0)),
                Ok(Ok(_)) => {
                    tracing::warn!("server returned no directive for the event");
                    None
                }
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "could not report crash; spooling");
                    None
                }
                Err(_) => {
                    tracing::warn!(?deadline, "server did not answer in time; spooling");
                    None
                }
            }
        })
    }

    /// Delete a core the server has told us it does not need.
    fn drop_core(&self, record: &CoredumpRecord) {
        if !self.config.delete_declined_cores {
            return;
        }
        if let Some(path) = record.core_path() {
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::debug!(path = %path.display(), "core not wanted; removed"),
                Err(err) => tracing::debug!(error = %err, "could not remove core"),
            }
        }
    }

    fn write_pending(
        &self,
        report: blankres_report::report::Report,
        directive: PayloadDirective,
        awaiting_directive: bool,
    ) -> std::io::Result<PathBuf> {
        let pending = PendingUpload {
            report,
            directive,
            written_at: now_secs(),
            awaiting_directive,
        };
        write_pending(&self.config.crash_dir, &pending)
    }

    /// Try to send everything that failed to reach the server earlier.
    pub async fn drain_spool(&self) {
        let Ok(pending) = self.spool.drain_list() else {
            return;
        };
        if pending.is_empty() {
            return;
        }

        let events: Vec<CrashEvent> = pending.iter().map(|(_, event)| event.clone()).collect();
        match self.client.send_events(&events).await {
            Ok(directives) => {
                for ((path, _), directive) in pending.iter().zip(directives) {
                    self.spool.remove(path);
                    // A spooled crash's core is very likely gone by now, and the offer may have
                    // expired; the event itself is what mattered.
                    if directive.need_payload {
                        tracing::debug!("server wanted a payload for a spooled event; skipping");
                    }
                }
                tracing::info!(count = events.len(), "drained spooled events");
            }
            Err(err) => tracing::debug!(error = %err, "spool drain failed; will retry"),
        }
    }
}

/// The directive stood in for a server that could not be reached.
///
/// `need_payload` is true because we do not know that it is false, and the honest default when a
/// crash cannot be reported is to ask the person it happened to. No upload token is invented: the
/// real one is fetched when they choose to send.
fn unconfirmed_directive() -> PayloadDirective {
    PayloadDirective {
        id: String::new(),
        need_payload: true,
        upload_token: None,
        max_bytes: None,
        expires_at: None,
    }
}

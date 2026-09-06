//! The daemon's decision loop: journal entry in, telemetry event out, and — only when the server
//! asks — a pending payload written for the user to review.

use std::path::PathBuf;

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
use crate::state::{State, RATE_LIMIT};

/// What happened to one crash, for logging and for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The user has declined this signature, or the executable is over its rate limit.
    Suppressed(String),
    /// Reported; the server did not want a core, and it has been deleted.
    ReportedCoreDropped { signature: String },
    /// Reported; the server asked for a payload, which is now awaiting consent.
    AwaitingConsent { signature: String, path: PathBuf },
    /// Could not reach the server; the event is spooled for a later attempt.
    Spooled { signature: String },
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
    /// The ordering here is the whole design: suppression is checked before collection, stage 1 is
    /// built and sent before anything expensive happens, and stage 2 runs only if the answer came
    /// back asking for it.
    pub async fn handle_coredump(
        &self,
        record: &CoredumpRecord,
        state: &mut State,
    ) -> std::io::Result<Outcome> {
        let executable = record.executable().unwrap_or("unknown").to_owned();

        // Cheapest possible gate, before any collection at all.
        let seen = state.charge_rate_limit(&executable, now_secs());
        if seen >= RATE_LIMIT {
            return Ok(Outcome::Suppressed(format!(
                "{executable} is over its rate limit ({seen} in the last hour)"
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

        let directive = match self.send(&event).await {
            Some(directive) => directive,
            None => {
                let _ = self.spool.push(&event);
                return Ok(Outcome::Spooled {
                    signature: event.signature.hash,
                });
            }
        };

        self.act_on(event, directive, record).await
    }

    /// Send a stage-1 event, returning `None` when the server could not be reached.
    async fn send(&self, event: &CrashEvent) -> Option<PayloadDirective> {
        match self.client.send_events(std::slice::from_ref(event)).await {
            Ok(mut directives) if !directives.is_empty() => Some(directives.remove(0)),
            Ok(_) => None,
            Err(err) => {
                tracing::warn!(error = %err, "could not report crash; spooling");
                None
            }
        }
    }

    /// Do what the directive says.
    async fn act_on(
        &self,
        event: CrashEvent,
        directive: PayloadDirective,
        record: &CoredumpRecord,
    ) -> std::io::Result<Outcome> {
        let signature = event.signature.hash.clone();

        if !directive.is_actionable(now_secs()) {
            // The common case: the server already has enough cores for this bug. Reclaim the disk
            // that apport would have kept indefinitely.
            if self.config.delete_declined_cores {
                if let Some(path) = record.core_path() {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {
                            tracing::debug!(path = %path.display(), "core not wanted; removed")
                        }
                        Err(err) => tracing::debug!(error = %err, "could not remove core"),
                    }
                }
            }
            return Ok(Outcome::ReportedCoreDropped { signature });
        }

        // Only now is expensive collection justified.
        let mut budget = Budget::stage2();
        let report = self
            .stage2
            .collect_within(event, directive.id.clone(), record, &mut budget);

        tracing::info!(
            signature = %&signature[..12],
            bytes = report.transfer_size(),
            elapsed = ?budget.elapsed(),
            "stage 2 collected; awaiting consent"
        );

        let pending = PendingUpload {
            report,
            directive,
            written_at: now_secs(),
        };
        let path = write_pending(&self.config.crash_dir, &pending)?;

        Ok(Outcome::AwaitingConsent { signature, path })
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

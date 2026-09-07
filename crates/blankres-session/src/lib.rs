//! The consent layer, shared by the CLI and the GTK front end.
//!
//! Both interfaces present the same three choices over the same data, so the logic lives here
//! once. In particular *nothing* uploads without going through [`ReportSession::send`], which is
//! the only place that reads the upload token.

pub mod store;

pub use store::{
    declined_path, ensure_user_dir, user_dir, write_pending, Declined, PendingEntry, PendingStore,
};

use blankres_client::{Client, ClientError, UploadReceipt};
use blankres_i18n::Catalog;
use blankres_report::report::Attachment;

/// What the user decided about one crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Upload the payload.
    Send,
    /// Discard this one, but stay willing to be asked about the next.
    Discard,
    /// Never ask about this signature again.
    DeclineForever,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("this report's upload window has expired; the server is no longer waiting for it")]
    Expired,
    #[error(transparent)]
    Upload(#[from] ClientError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// One crash, one decision.
pub struct ReportSession<'a> {
    store: &'a PendingStore,
    entry: PendingEntry,
    catalog: Catalog,
}

impl<'a> ReportSession<'a> {
    /// A session using the language the environment asks for.
    pub fn new(store: &'a PendingStore, entry: PendingEntry) -> Self {
        Self::with_catalog(store, entry, Catalog::detect())
    }

    /// A session in an explicit language, so tests are not at the mercy of the ambient locale.
    pub fn with_catalog(store: &'a PendingStore, entry: PendingEntry, catalog: Catalog) -> Self {
        Self {
            store,
            entry,
            catalog,
        }
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn entry(&self) -> &PendingEntry {
        &self.entry
    }

    /// Everything that would be transmitted, as label/value pairs.
    ///
    /// The front ends render this verbatim. It is not a summary: the user is being asked to send
    /// a memory snapshot of their own process, and they can only meaningfully agree to that if
    /// they can see what it is attached to.
    pub fn disclosure(&self) -> Vec<(String, String)> {
        let t = &self.catalog;
        let report = &self.entry.pending.report;
        let event = &report.event;
        let mut rows = vec![
            (t.label_program().to_owned(), event.executable.clone()),
            (
                t.label_signal().to_owned(),
                event
                    .signal_name
                    .clone()
                    .or_else(|| event.signal.map(|s| s.to_string()))
                    .unwrap_or_else(|| t.unknown().to_owned()),
            ),
            (
                t.label_package().to_owned(),
                match (&event.package.name, &event.package.version) {
                    (Some(name), Some(version)) => format!("{name} {version}"),
                    (Some(name), None) => name.clone(),
                    _ => t.not_from_a_package().to_owned(),
                },
            ),
            (
                t.label_operating_system().to_owned(),
                format!("{} {}", event.system.distro, event.system.distro_version),
            ),
            (
                t.label_kernel().to_owned(),
                event.system.kernel_version.clone(),
            ),
            (
                t.label_signature().to_owned(),
                format!(
                    "{} ({:?})",
                    &event.signature.hash[..16.min(event.signature.hash.len())],
                    event.signature.precision
                ),
            ),
        ];

        if !report.command_line.is_empty() {
            rows.push((
                t.label_command_line().to_owned(),
                report.command_line.join(" "),
            ));
        }

        if !report.stack_trace.is_empty() {
            let frames: Vec<String> = report
                .stack_trace
                .iter()
                .take(12)
                .map(|frame| {
                    frame
                        .function
                        .clone()
                        .or_else(|| frame.module.clone())
                        .unwrap_or_else(|| "??".to_owned())
                })
                .collect();
            rows.push((t.label_stack_trace().to_owned(), frames.join("\n")));
        }

        for (name, value) in &report.environment {
            rows.push((t.label_environment_named(name), value.clone()));
        }
        if report.environment_withheld > 0 {
            rows.push((
                t.label_environment().to_owned(),
                t.variables_withheld(report.environment_withheld),
            ));
        }

        for modified in &report.modified_files {
            rows.push((
                t.label_modified_file().to_owned(),
                t.from_package(&modified.path.display().to_string(), &modified.package),
            ));
        }

        for attachment in &report.attachments {
            let description = match attachment {
                Attachment::Inline { content, .. } => t.bytes_of_text(content.len()),
                Attachment::File { size, .. } => t.memory_snapshot_of_size(&human_size(*size)),
            };
            rows.push((t.label_attachment(attachment.name()), description));
        }

        for skipped in &report.skipped {
            rows.push((t.label_not_collected(&skipped.name), skipped.reason.clone()));
        }

        rows
    }

    /// A one-line summary of the transfer, for the headline.
    pub fn transfer_summary(&self) -> String {
        let size = self.entry.transfer_size();
        if size == 0 {
            return self.catalog.no_attachments().to_owned();
        }
        self.catalog.includes_size(&human_size(size))
    }

    /// Whether the server is still waiting for this payload.
    pub fn is_actionable(&self, now: u64) -> bool {
        self.entry.pending.is_actionable(now)
    }

    /// Carry out the user's decision.
    pub async fn decide(
        &self,
        decision: Decision,
        client: &Client,
    ) -> Result<Option<UploadReceipt>, SessionError> {
        match decision {
            Decision::Send => {
                let receipt = self.send(client).await?;
                Ok(Some(receipt))
            }
            Decision::Discard => {
                self.discard();
                Ok(None)
            }
            Decision::DeclineForever => {
                self.decline_forever()?;
                Ok(None)
            }
        }
    }

    /// Upload the payload. The only place the upload token is used.
    pub async fn send(&self, client: &Client) -> Result<UploadReceipt, SessionError> {
        let now = now_secs();
        if !self.entry.pending.is_actionable(now) {
            return Err(SessionError::Expired);
        }

        let receipt = client
            .upload_report(&self.entry.pending.report, &self.entry.pending.directive)
            .await?;

        // The core has done its job; keeping it after a successful upload is pure disk cost.
        self.store.remove_core(&self.entry);
        self.store.remove(&self.entry);

        Ok(receipt)
    }

    /// Throw this report away without sending anything.
    pub fn discard(&self) {
        self.store.remove_core(&self.entry);
        self.store.remove(&self.entry);
    }

    /// Discard, and record that this signature should never be raised again.
    pub fn decline_forever(&self) -> Result<(), SessionError> {
        let mut declined = Declined::load(self.store.crash_dir(), self.store.uid());
        declined.add(self.entry.pending.report.event.signature.hash.clone());
        declined.save(self.store.crash_dir(), self.store.uid())?;
        self.discard();
        Ok(())
    }
}

/// Sizes as a person would say them. Crash payloads span kilobytes to gigabytes, and "412 MB" is
/// the number that decides whether someone consents.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The uid of the current process, for locating this user's pending reports.
pub fn current_uid() -> u32 {
    // Reading it from `/proc/self/status` keeps this crate free of a libc dependency, and the
    // fallback of 0 is harmless: it just means an empty list for a user with no crashes.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
        })
        .unwrap_or(0)
}

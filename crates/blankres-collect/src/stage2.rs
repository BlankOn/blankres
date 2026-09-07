//! Stage 2: assemble the full payload.
//!
//! Reached only when the server issued a directive asking for it, so this is the one place where
//! spending real I/O is correct. Every collector is still individually bounded and individually
//! skippable: a report missing its log tail is far better than a machine stalled collecting one.

use std::collections::BTreeMap;
use std::path::PathBuf;

use blankres_report::event::CrashEvent;
use blankres_report::redact::{filter_environ_block, scrub_cmdline_block};
use blankres_report::report::{Attachment, Report, SkippedCollector, CORE_DUMP_ATTACHMENT};
use blankres_report::signature::parse_journal_stack_trace;

use crate::budget::Budget;
use crate::pkg::PackageBackend;
use crate::record::CoredumpRecord;
use crate::sys::Filesystem;

/// Largest inline attachment. Beyond this a text file is truncated rather than embedded whole.
const MAX_INLINE_BYTES: u64 = 256 * 1024;

/// Ceiling on how many mapped objects get hashed, so a process with a thousand plugins cannot
/// turn integrity checking back into apport's problem.
const MAX_VERIFIED_FILES: usize = 64;

pub struct Stage2Collector<F: Filesystem, P: PackageBackend> {
    fs: F,
    packages: P,
}

impl<F: Filesystem, P: PackageBackend> Stage2Collector<F, P> {
    pub fn new(fs: F, packages: P) -> Self {
        Self { fs, packages }
    }

    /// The filesystem seam, so callers and tests can observe what was touched.
    pub fn filesystem(&self) -> &F {
        &self.fs
    }

    /// Build the payload for an event the server asked about.
    pub fn collect(
        &self,
        event: CrashEvent,
        directive_id: impl Into<String>,
        record: &CoredumpRecord,
    ) -> Report {
        let mut budget = Budget::stage2();
        self.collect_within(event, directive_id, record, &mut budget)
    }

    pub fn collect_within(
        &self,
        event: CrashEvent,
        directive_id: impl Into<String>,
        record: &CoredumpRecord,
        budget: &mut Budget,
    ) -> Report {
        let mut report = self.collect_without_verification(event, directive_id, record, budget);
        self.verify_into(&mut report, record, budget);
        report
    }

    /// Everything that comes straight from the journal record, with no disk access beyond a stat
    /// of the core.
    ///
    /// This is the half that can run while the stage-1 request is still in flight: it costs
    /// microseconds, where hashing a process's mapped libraries costs real I/O and is therefore
    /// deferred until we know the payload is actually wanted.
    pub fn collect_without_verification(
        &self,
        event: CrashEvent,
        directive_id: impl Into<String>,
        record: &CoredumpRecord,
        budget: &mut Budget,
    ) -> Report {
        let mut skipped = Vec::new();

        let command_line = record
            .command_line()
            .map(scrub_cmdline_block)
            .unwrap_or_default();

        let (environment, environment_withheld) = record
            .environ()
            .map(filter_environ_block)
            .unwrap_or_else(|| (BTreeMap::new(), 0));

        let stack_trace = parse_journal_stack_trace(&record.message);

        let mut attachments = Vec::new();

        // The core dump: referenced, never read. Its bytes are streamed from this path at upload
        // time in the zstd frames systemd already wrote.
        if let Some(path) = record.core_path() {
            match self.fs.metadata_len(&path) {
                Ok(size) => attachments.push(Attachment::File {
                    name: CORE_DUMP_ATTACHMENT.to_owned(),
                    path,
                    size,
                    compression: Some("zstd".to_owned()),
                }),
                Err(err) => skipped.push(SkippedCollector {
                    name: CORE_DUMP_ATTACHMENT.to_owned(),
                    reason: format!("core dump unavailable: {err}"),
                }),
            }
        }

        for (name, content) in [
            ("proc-maps", record.proc_maps()),
            ("proc-status", record.proc_status()),
        ] {
            let Some(content) = content else { continue };
            match budget.charge(content.len() as u64) {
                Ok(()) => attachments.push(Attachment::Inline {
                    name: name.to_owned(),
                    content: truncate(content, MAX_INLINE_BYTES),
                }),
                Err(reason) => skipped.push(SkippedCollector {
                    name: name.to_owned(),
                    reason: reason.to_string(),
                }),
            }
        }

        Report {
            event,
            directive_id: directive_id.into(),
            command_line,
            environment,
            environment_withheld,
            uid: record.uid(),
            stack_trace,
            modified_files: Vec::new(),
            attachments,
            skipped,
        }
    }

    /// Hash the executable and the libraries mapped at crash time, recording any that no longer
    /// match what dpkg installed.
    ///
    /// Deliberately separate and deliberately last: this is the only part of stage 2 that reads
    /// significant amounts of data, so it runs once the payload is known to be worth keeping.
    pub fn verify_into(&self, report: &mut Report, record: &CoredumpRecord, budget: &mut Budget) {
        match budget.check_time() {
            Ok(()) => {
                let mut candidates = record.mapped_files();
                // The executable first: it is the file most likely to matter and the one we least
                // want dropped by the cap.
                if let Some(exe) = record.executable() {
                    let exe = PathBuf::from(exe);
                    candidates.retain(|p| p != &exe);
                    candidates.insert(0, exe);
                }
                candidates.truncate(MAX_VERIFIED_FILES);
                report.modified_files = self.packages.verify(&candidates);
            }
            Err(reason) => report.skipped.push(SkippedCollector {
                name: "package-verification".to_owned(),
                reason: reason.to_string(),
            }),
        }
    }

    /// Attach a log file, truncated to its tail.
    ///
    /// The end of a log is where the crash is; the beginning is boot noise. Reading the tail also
    /// bounds the cost regardless of how large the file has grown.
    pub fn attach_log(
        &self,
        report: &mut Report,
        name: &str,
        path: &std::path::Path,
        budget: &mut Budget,
    ) {
        let size = match self.fs.metadata_len(path) {
            Ok(size) => size,
            Err(err) => {
                report.skipped.push(SkippedCollector {
                    name: name.to_owned(),
                    reason: format!("unavailable: {err}"),
                });
                return;
            }
        };

        let wanted = size.min(MAX_INLINE_BYTES);
        if let Err(reason) = budget.charge(wanted) {
            report.skipped.push(SkippedCollector {
                name: name.to_owned(),
                reason: reason.to_string(),
            });
            return;
        }

        match self.fs.read_to_string(path) {
            Ok(content) => report.attachments.push(Attachment::Inline {
                name: name.to_owned(),
                content: tail(&content, MAX_INLINE_BYTES as usize),
            }),
            Err(err) => report.skipped.push(SkippedCollector {
                name: name.to_owned(),
                reason: format!("unreadable: {err}"),
            }),
        }
    }
}

fn truncate(content: &str, limit: u64) -> String {
    let limit = limit as usize;
    if content.len() <= limit {
        return content.to_owned();
    }
    let mut cut = limit;
    while cut > 0 && !content.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n[truncated]", &content[..cut])
}

fn tail(content: &str, limit: usize) -> String {
    if content.len() <= limit {
        return content.to_owned();
    }
    let mut start = content.len() - limit;
    while start < content.len() && !content.is_char_boundary(start) {
        start += 1;
    }
    format!("[truncated]\n{}", &content[start..])
}

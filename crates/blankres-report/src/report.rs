//! Stage 2: the full payload, assembled only after the server asks for it.
//!
//! A [`Report`] embeds the stage-1 [`CrashEvent`] verbatim rather than restating its fields, so
//! the server can verify the payload belongs to the event it issued a token for.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::event::CrashEvent;
use crate::signature::Frame;

/// An attachment, either carried inline or referenced on disk.
///
/// Core dumps are always [`Attachment::File`]: they are referenced in place and streamed at upload
/// time, never read into memory and never recompressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "storage", rename_all = "snake_case")]
pub enum Attachment {
    /// Small text collected into the report itself.
    Inline { name: String, content: String },
    /// A file left where it is until upload.
    File {
        name: String,
        path: PathBuf,
        size: u64,
        /// e.g. `zstd`, when the file on disk is already compressed and must be passed through.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        compression: Option<String>,
    },
}

impl Attachment {
    pub fn name(&self) -> &str {
        match self {
            Attachment::Inline { name, .. } | Attachment::File { name, .. } => name,
        }
    }

    /// Bytes this attachment will contribute to an upload.
    pub fn transfer_size(&self) -> u64 {
        match self {
            Attachment::Inline { content, .. } => content.len() as u64,
            Attachment::File { size, .. } => *size,
        }
    }
}

/// Result of verifying a package file against its recorded checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifiedFile {
    pub path: PathBuf,
    pub package: String,
}

/// A collector that did not run to completion, and why.
///
/// Recorded rather than dropped: a missing field must be distinguishable from a field that was
/// collected and found empty, otherwise budget-skipped data silently looks like evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedCollector {
    pub name: String,
    pub reason: String,
}

/// The stage-2 payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The stage-1 event this payload answers, unchanged.
    pub event: CrashEvent,
    /// Directive id returned by `POST /v1/events`.
    pub directive_id: String,
    /// Scrubbed argv. See [`crate::redact::scrub_command_line`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_line: Vec<String>,
    /// Allowlisted environment. See [`crate::redact::filter_environment`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    /// How many environment variables were withheld by redaction.
    #[serde(default)]
    pub environment_withheld: usize,
    /// Uid the crashed process ran as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Full stack trace, where stage 1 only hashed the top frames.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_trace: Vec<Frame>,
    /// Package files whose checksums no longer match. A non-empty list means the crash may be the
    /// user's local modification rather than a bug in the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modified_files: Vec<ModifiedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedCollector>,
}

impl Report {
    /// Total bytes an upload of this report will transfer, for checking against
    /// [`crate::event::PayloadDirective::max_bytes`] *before* doing the work.
    pub fn transfer_size(&self) -> u64 {
        self.attachments.iter().map(Attachment::transfer_size).sum()
    }

    /// The core dump attachment, if one is present.
    pub fn core_dump(&self) -> Option<&Attachment> {
        self.attachments
            .iter()
            .find(|a| a.name() == CORE_DUMP_ATTACHMENT)
    }
}

/// Conventional attachment name for the core dump.
pub const CORE_DUMP_ATTACHMENT: &str = "core-dump";

/// A stage-2 payload waiting for the user's decision.
///
/// Written to `/var/crash` by the daemon and read by whichever front end the user has. It pairs
/// the collected payload with the capability the server issued, because neither is useful alone:
/// the report cannot be uploaded without the directive, and the directive expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpload {
    pub report: Report,
    pub directive: crate::event::PayloadDirective,
    /// Unix seconds when the daemon wrote this file.
    pub written_at: u64,
    /// True when the server could not be reached, so nobody has yet said whether the payload is
    /// wanted. The report is still shown to the user: a crash that cannot be reported is not a
    /// crash that should be hidden. The directive is obtained when they choose to send.
    #[serde(default)]
    pub awaiting_directive: bool,
}

impl PendingUpload {
    /// Whether this can still be sent, or whether the server's offer has lapsed.
    ///
    /// A report still awaiting a directive is always actionable: there is no offer to expire yet,
    /// and the point of showing it is to let the user decide before one exists.
    pub fn is_actionable(&self, now: u64) -> bool {
        self.awaiting_directive || self.directive.is_actionable(now)
    }

    /// Filename to use under `/var/crash`.
    ///
    /// Keyed by executable, uid *and* signature. The signature matters: without it two different
    /// bugs in the same program share a filename, so the second crash silently overwrites the
    /// first and takes its upload token with it.
    pub fn file_name(&self) -> String {
        let exe = self
            .report
            .event
            .executable
            .trim_start_matches('/')
            .replace('/', "_");
        let uid = self.report.uid.unwrap_or(0);
        let signature = &self.report.event.signature.hash;
        let short = &signature[..12.min(signature.len())];
        format!("{exe}.{uid}.{short}.report")
    }
}

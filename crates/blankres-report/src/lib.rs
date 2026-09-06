//! Shared vocabulary for blankres: the two-stage reporting schema, crash signatures, redaction,
//! and a reader for apport's `.crash` format.
//!
//! The daemon, the CLI, the GTK client and the ingest server all compile against this crate, so
//! the wire schema is defined in exactly one place. See `event` for stage 1 (the cheap telemetry
//! event and the server's directive) and `report` for stage 2 (the full payload).

pub mod apport;
pub mod event;
pub mod redact;
pub mod report;
pub mod signature;

pub use event::{
    CrashEvent, DirectiveBatch, EventBatch, PackageInfo, PayloadDirective, ReportKind, SystemInfo,
    SCHEMA_VERSION,
};
pub use report::{
    Attachment, ModifiedFile, PendingUpload, Report, SkippedCollector, CORE_DUMP_ATTACHMENT,
};
pub use signature::{Frame, Precision, Signature};

/// Version reported in [`CrashEvent::client_version`].
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Translate a signal number to its name, for display and for the event.
pub fn signal_name(signal: u32) -> Option<&'static str> {
    Some(match signal {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        11 => "SIGSEGV",
        31 => "SIGSYS",
        5 => "SIGTRAP",
        3 => "SIGQUIT",
        _ => return None,
    })
}

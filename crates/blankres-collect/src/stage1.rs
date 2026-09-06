//! Stage 1: build the telemetry event.
//!
//! The rules this module exists to enforce, all of which are covered by tests:
//!
//! * no subprocess is spawned;
//! * the core dump is never opened, only stat'ed for its size;
//! * everything else comes from the journal record or from state read once at daemon start.

use blankres_report::event::{CrashEvent, PackageInfo, ReportKind, SystemInfo, SCHEMA_VERSION};
use blankres_report::signature::{parse_journal_stack_trace, Signature};
use blankres_report::{signal_name, CLIENT_VERSION};

use crate::budget::{Budget, Exhausted};
use crate::pkg::PackageBackend;
use crate::record::CoredumpRecord;
use crate::sys::Filesystem;

/// Builds stage-1 events. Holds the state that is expensive to obtain and constant between
/// crashes, so the per-crash path stays arithmetic.
pub struct Stage1Collector<F: Filesystem, P: PackageBackend> {
    fs: F,
    packages: P,
    system: SystemInfo,
    machine_id: String,
}

impl<F: Filesystem, P: PackageBackend> Stage1Collector<F, P> {
    pub fn new(fs: F, packages: P, system: SystemInfo, machine_id: String) -> Self {
        Self {
            fs,
            packages,
            system,
            machine_id,
        }
    }

    pub fn packages(&self) -> &P {
        &self.packages
    }

    /// The filesystem seam, so callers and tests can observe what was touched.
    pub fn filesystem(&self) -> &F {
        &self.fs
    }

    /// Build the event for one crash.
    ///
    /// `crash_count` is this signature's running total on this machine, which the caller keeps —
    /// it is state about the host, not about the crash.
    pub fn collect(&self, record: &CoredumpRecord, crash_count: u32) -> CrashEvent {
        let mut budget = Budget::stage1();
        self.collect_within(record, crash_count, &mut budget)
    }

    /// As [`Self::collect`], with a caller-supplied budget so the daemon can log what was used.
    pub fn collect_within(
        &self,
        record: &CoredumpRecord,
        crash_count: u32,
        budget: &mut Budget,
    ) -> CrashEvent {
        let executable = record.executable().unwrap_or("unknown").to_owned();
        let signal = record.signal();

        let package = self
            .packages
            .owner(std::path::Path::new(&executable))
            .unwrap_or_default();

        let signature = self.signature(record, &executable, signal, &package);
        let (core_available, core_size) = self.core_status(record, budget);

        CrashEvent {
            schema: SCHEMA_VERSION,
            signature,
            kind: ReportKind::NativeCrash,
            timestamp: record.timestamp,
            executable,
            signal,
            signal_name: signal.and_then(signal_name).map(str::to_owned),
            package,
            system: self.system.clone(),
            machine_id: self.machine_id.clone(),
            crash_count,
            client_version: CLIENT_VERSION.to_owned(),
            core_available,
            core_size,
        }
    }

    /// Prefer the symbolized trace; fall back to the coarse signature when systemd could not
    /// unwind. The precision is recorded in the signature itself so the server knows which it got.
    fn signature(
        &self,
        record: &CoredumpRecord,
        executable: &str,
        signal: Option<u32>,
        package: &PackageInfo,
    ) -> Signature {
        let frames = parse_journal_stack_trace(&record.message);
        if frames.is_empty() {
            return Signature::coarse(executable, signal, package.version.as_deref());
        }
        Signature::from_frames(&frames, signal, executable)
    }

    /// Whether a core exists and how large it is.
    ///
    /// A `stat` only. Opening the core here would defeat the point of the stage split, and the
    /// size is exactly what lets the server decline a transfer that is not worth it.
    fn core_status(&self, record: &CoredumpRecord, budget: &mut Budget) -> (bool, Option<u64>) {
        let Some(path) = record.core_path() else {
            return (false, None);
        };
        if budget.check_time().is_err() {
            return (false, None);
        }
        match self.fs.metadata_len(&path) {
            Ok(size) => (true, Some(size)),
            Err(_) => (false, None),
        }
    }
}

/// Whether an event should be sent at all.
///
/// Checked before any collection, so a crash storm costs a hash comparison rather than a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suppression {
    /// The user chose "never for this problem".
    UserDeclined,
    /// Too many events for this executable in the current window.
    RateLimited { seen: u32, limit: u32 },
}

impl std::fmt::Display for Suppression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Suppression::UserDeclined => write!(f, "user declined this signature"),
            Suppression::RateLimited { seen, limit } => {
                write!(f, "rate limited ({seen} seen, limit {limit})")
            }
        }
    }
}

/// Reports the budget was unable to honour, for logging.
pub type BudgetOutcome = Result<(), Exhausted>;

//! Turning failed package operations into crash reports.
//!
//! A maintainer script that exits non-zero leaves the system in a half-configured state and is,
//! from the user's point of view, exactly as much of a failure as a segfault. apport reports these
//! too. There is never a core dump involved, so this path stops at stage 1 by construction — which
//! also means it can run as a short-lived hook rather than needing the daemon.

use blankres_report::event::{CrashEvent, PackageInfo, ReportKind, SystemInfo, SCHEMA_VERSION};
use blankres_report::signature::{Frame, Signature};
use blankres_report::CLIENT_VERSION;

pub const DPKG_LOG: &str = "/var/log/dpkg.log";
pub const APT_TERM_LOG: &str = "/var/log/apt/term.log";

/// One failed package operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFailure {
    /// Log timestamp, `YYYY-MM-DD HH:MM:SS`, used to avoid re-reporting on the next apt run.
    pub logged_at: String,
    pub package: String,
    /// The dpkg state that revealed the failure, e.g. `half-configured`.
    pub state: String,
    /// The operation dpkg was performing, when known.
    pub operation: Option<String>,
}

impl PackageFailure {
    /// Build the stage-1 event.
    ///
    /// The signature is the package plus the failing state, so one broken postinst buckets
    /// together across every machine that hits it — which is the entire value of reporting these.
    pub fn to_event(
        &self,
        version: Option<String>,
        system: SystemInfo,
        machine_id: String,
        crash_count: u32,
        timestamp: u64,
    ) -> CrashEvent {
        let frames = vec![
            Frame {
                function: Some(format!("dpkg:{}", self.state)),
                module: None,
                module_offset: None,
            },
            Frame {
                function: Some(self.package.clone()),
                module: None,
                module_offset: None,
            },
        ];

        CrashEvent {
            schema: SCHEMA_VERSION,
            signature: Signature::from_frames(&frames, None, &self.package),
            kind: ReportKind::PackageFailure,
            timestamp,
            executable: format!("dpkg:{}", self.package),
            signal: None,
            signal_name: None,
            package: PackageInfo {
                name: Some(self.package.clone()),
                version,
                source: None,
            },
            system,
            machine_id,
            crash_count,
            client_version: CLIENT_VERSION.to_owned(),
            core_available: false,
            core_size: None,
        }
    }
}

/// dpkg states that mean an operation failed rather than completed.
const FAILURE_STATES: &[&str] = &[
    "half-configured",
    "half-installed",
    "triggers-awaited-failed",
];

/// Parse failures out of `dpkg.log`.
///
/// Lines look like:
///
/// ```text
/// 2026-09-07 03:14:21 status half-configured foo:amd64 1.0-1
/// 2026-09-07 03:14:21 configure foo:amd64 1.0-1 <none>
/// ```
///
/// Only entries strictly newer than `after` are returned, so a hook that runs on every apt
/// invocation does not re-report the same failure forever.
pub fn parse_dpkg_log(log: &str, after: Option<&str>) -> Vec<PackageFailure> {
    let mut failures = Vec::new();

    for line in log.lines() {
        let mut parts = line.split_whitespace();
        let (Some(date), Some(time), Some(kind)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if kind != "status" {
            continue;
        }
        let Some(state) = parts.next() else { continue };
        if !FAILURE_STATES.contains(&state) {
            continue;
        }
        let Some(package) = parts.next() else {
            continue;
        };

        let logged_at = format!("{date} {time}");
        if let Some(after) = after {
            // String comparison is correct here: the timestamp format sorts lexicographically.
            if logged_at.as_str() <= after {
                continue;
            }
        }

        failures.push(PackageFailure {
            logged_at,
            // `foo:amd64` -> `foo`, matching how the package is named everywhere else.
            package: package.split(':').next().unwrap_or(package).to_owned(),
            state: state.to_owned(),
            operation: None,
        });
    }

    // dpkg passes through a failure state more than once for a single broken package; one report
    // per package per run is what a human would call one failure.
    failures.dedup_by(|a, b| a.package == b.package && a.state == b.state);
    failures
}

/// The tail of apt's terminal log, which is where a maintainer script's actual error message is.
///
/// Bounded: this is diagnostic colour, not the report, and the log can be enormous after a
/// distribution upgrade.
pub fn terminal_log_tail(log: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

/// The newest timestamp among a set of failures, for the state file.
pub fn newest_timestamp(failures: &[PackageFailure]) -> Option<String> {
    failures.iter().map(|f| f.logged_at.clone()).max()
}

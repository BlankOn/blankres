//! Kernel oops detection.
//!
//! An oops is not one log line, it is a burst of them — a header, a register dump, a call trace,
//! and often a second copy from a different CPU. Filing one report per line would be useless, so
//! lines are coalesced into a single report and deduplicated on the first symbol.

use blankres_report::event::{CrashEvent, PackageInfo, ReportKind, SystemInfo, SCHEMA_VERSION};
use blankres_report::signature::{Frame, Precision, Signature};
use blankres_report::CLIENT_VERSION;

/// Markers that begin an oops.
const OOPS_MARKERS: &[&str] = &[
    "Oops:",
    "kernel BUG at",
    "BUG: unable to handle",
    "BUG: kernel NULL pointer dereference",
    "general protection fault",
    "Unable to handle kernel",
    "kernel panic",
    "Kernel panic",
];

/// How long after the first line an oops is still considered the same event.
pub const COALESCE_WINDOW_SECS: u64 = 10;

/// True when a kernel log line begins an oops.
pub fn starts_oops(line: &str) -> bool {
    OOPS_MARKERS.iter().any(|marker| line.contains(marker))
}

/// Accumulates the lines of one oops.
#[derive(Debug, Clone)]
pub struct OopsBuilder {
    pub started_at: u64,
    pub lines: Vec<String>,
}

impl OopsBuilder {
    pub fn new(started_at: u64, first_line: impl Into<String>) -> Self {
        Self {
            started_at,
            lines: vec![first_line.into()],
        }
    }

    pub fn push(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    /// Whether a line arriving at `now` still belongs to this oops.
    pub fn accepts(&self, now: u64) -> bool {
        now.saturating_sub(self.started_at) <= COALESCE_WINDOW_SECS
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// Build the stage-1 event for this oops.
    ///
    /// The signature comes from the call trace's frames, so the same oops on a thousand machines
    /// buckets together exactly as a user-space crash does.
    pub fn to_event(&self, system: SystemInfo, machine_id: String, crash_count: u32) -> CrashEvent {
        let frames = parse_call_trace(&self.lines);
        let executable = format!("kernel:{}", system.kernel_version);

        let signature = if frames.is_empty() {
            let mut coarse = Signature::coarse(&summary(&self.lines), None, None);
            coarse.precision = Precision::Coarse;
            coarse
        } else {
            Signature::from_frames(&frames, None, &executable)
        };

        CrashEvent {
            schema: SCHEMA_VERSION,
            signature,
            kind: ReportKind::KernelOops,
            timestamp: self.started_at,
            executable,
            signal: None,
            signal_name: None,
            package: PackageInfo::default(),
            system,
            machine_id,
            crash_count,
            client_version: CLIENT_VERSION.to_owned(),
            // There is no core dump for an oops; the journal text is the whole evidence.
            core_available: false,
            core_size: None,
        }
    }
}

/// The oops line most worth showing a human.
fn summary(lines: &[String]) -> String {
    lines
        .iter()
        .find(|line| starts_oops(line))
        .cloned()
        .unwrap_or_else(|| lines.first().cloned().unwrap_or_default())
}

/// Extract symbol names from a kernel call trace.
///
/// Kernel traces look like `? __die+0x23/0x70` or `do_page_fault+0x1c9/0x4c0`. The offsets shift
/// with every kernel build, so only the symbol survives into the signature.
pub fn parse_call_trace(lines: &[String]) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut in_trace = false;

    for line in lines {
        let trimmed = line.trim();
        if trimmed.contains("Call Trace:") {
            in_trace = true;
            continue;
        }
        if !in_trace {
            continue;
        }

        // `? symbol+0xoff/0xlen [module]`, with the leading `?` marking an unreliable frame.
        let candidate = trimmed.trim_start_matches('?').trim();
        let Some(symbol) = candidate.split('+').next() else {
            continue;
        };
        let symbol = symbol.trim();
        if symbol.is_empty() || symbol.contains(' ') || !candidate.contains('+') {
            // A line that is not a frame ends the trace.
            if !frames.is_empty() {
                break;
            }
            continue;
        }

        frames.push(Frame {
            function: Some(symbol.to_owned()),
            module: None,
            module_offset: None,
        });
    }

    frames
}

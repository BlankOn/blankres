//! Crash signatures: the dedup key that stage 1 must produce *without opening the core dump*.
//!
//! Two precisions, in preference order:
//!
//! * [`Precision::Precise`] — derived from the symbolized stack trace that `systemd-coredump`
//!   embeds in its journal message when it is built against libdw.
//! * [`Precision::Coarse`] — the fallback when no trace is available: executable, signal and
//!   package version only. Much weaker, so it is reported to the server rather than hidden.
//!
//! Frames are always normalized to *module-relative* offsets. Absolute addresses shift on every
//! boot under ASLR, so hashing them would produce a fresh signature per crash and silently defeat
//! deduplication while still looking like it works.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How much the signature can be trusted to identify one distinct bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    /// Hashed from a symbolized stack trace.
    Precise,
    /// Hashed from executable and signal alone; distinct bugs in one binary will collide.
    Coarse,
}

/// One normalized stack frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// Symbol name, if the trace carried one. `n/a` from systemd is stored as `None`.
    pub function: Option<String>,
    /// Object the frame belongs to, e.g. `libc.so.6`.
    pub module: Option<String>,
    /// Offset within `module`. Stable across boots; the absolute address is not.
    pub module_offset: Option<u64>,
}

impl Frame {
    /// The string this frame contributes to the hash.
    ///
    /// A symbol is preferred because it survives recompilation of the surrounding library; the
    /// module offset is the next best thing, and an unidentifiable frame contributes a constant
    /// so that its *position* still matters.
    fn normalized(&self) -> String {
        if let Some(function) = &self.function {
            // Strip any `+0x1c` suffix so a one-instruction shift inside the same function does
            // not fork the signature.
            let base = function.split('+').next().unwrap_or(function).trim();
            if !base.is_empty() && base != "n/a" {
                return base.to_ascii_lowercase();
            }
        }
        match (&self.module, self.module_offset) {
            (Some(module), Some(offset)) => {
                format!("{}+{:#x}", module.to_ascii_lowercase(), offset)
            }
            (Some(module), None) => module.to_ascii_lowercase(),
            _ => "??".to_owned(),
        }
    }
}

/// A computed crash signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Hex-encoded SHA-256. This is the dedup key the server counts on.
    pub hash: String,
    pub precision: Precision,
    /// The normalized frame strings that produced `hash`, kept for debugging and for the UI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<String>,
}

/// How many leading frames participate. Deep enough to separate distinct bugs, shallow enough
/// that an unrelated change further down the stack does not split one bug into many.
const SIGNIFICANT_FRAMES: usize = 5;

/// Frames belonging to the crash-reporting machinery itself, skipped so that every SIGABRT does
/// not hash to the same thing.
const NOISE_PREFIXES: &[&str] = &[
    "__pthread_kill",
    "pthread_kill",
    "raise",
    "abort",
    "__libc_message",
    "__gi_raise",
    "__gi_abort",
    "__assert_fail",
    "__stack_chk_fail",
    "gsignal",
];

fn is_noise(normalized: &str) -> bool {
    NOISE_PREFIXES.iter().any(|p| normalized.starts_with(p))
}

impl Signature {
    /// Signature from a symbolized stack trace.
    ///
    /// Leading unwinder/abort frames are dropped first: they are identical for every abort and
    /// would collapse unrelated bugs into one bucket. If *every* frame is noise the trace is kept
    /// as-is rather than hashing nothing.
    pub fn from_frames(frames: &[Frame], signal: Option<u32>, executable: &str) -> Self {
        let normalized: Vec<String> = frames.iter().map(Frame::normalized).collect();
        let first_real = normalized.iter().position(|f| !is_noise(f)).unwrap_or(0);
        let significant: Vec<String> = normalized[first_real..]
            .iter()
            .take(SIGNIFICANT_FRAMES)
            .cloned()
            .collect();

        if significant.is_empty() {
            return Self::coarse(executable, signal, None);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"blankres-sig-v1\0");
        hasher.update(executable.as_bytes());
        hasher.update([0]);
        hasher.update(signal.unwrap_or(0).to_le_bytes());
        for frame in &significant {
            hasher.update([0]);
            hasher.update(frame.as_bytes());
        }

        Self {
            hash: hex::encode(hasher.finalize()),
            precision: Precision::Precise,
            frames: significant,
        }
    }

    /// Fallback signature for crashes with no usable stack trace.
    ///
    /// Deliberately includes the package version: without frames, a signature that ignored the
    /// version would merge a bug with its own fix.
    pub fn coarse(executable: &str, signal: Option<u32>, package_version: Option<&str>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"blankres-sig-v1-coarse\0");
        hasher.update(executable.as_bytes());
        hasher.update([0]);
        hasher.update(signal.unwrap_or(0).to_le_bytes());
        hasher.update([0]);
        hasher.update(package_version.unwrap_or("").as_bytes());

        Self {
            hash: hex::encode(hasher.finalize()),
            precision: Precision::Coarse,
            frames: Vec::new(),
        }
    }
}

/// Parse the stack trace `systemd-coredump` embeds in its journal message.
///
/// The relevant shape is:
///
/// ```text
/// Stack trace of thread 4242:
/// #0  0x00007f8a1b2c3d4e __pthread_kill_implementation (libc.so.6 + 0x8ab2c)
/// #1  0x00007f8a1b2ab476 raise (libc.so.6 + 0x42476)
/// #2  0x0000556677889900 n/a (/usr/bin/foo + 0x1234)
/// ```
///
/// Only the first `Stack trace of thread` block is read: systemd emits the crashing thread first
/// and the others are unrelated to the bug. Returns an empty vector when the message carries no
/// trace at all, which is the signal to fall back to [`Signature::coarse`].
pub fn parse_journal_stack_trace(message: &str) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut in_block = false;

    for line in message.lines() {
        let line = line.trim();
        if line.starts_with("Stack trace of thread") {
            // A second block means we have finished with the crashing thread.
            if in_block {
                break;
            }
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        match parse_frame(line) {
            Some(frame) => frames.push(frame),
            // Blank lines and continuation text end the block.
            None if line.is_empty() || !line.starts_with('#') => break,
            None => continue,
        }
    }

    frames
}

/// Parse one `#N  0xADDR symbol (module + 0xOFFSET)` line.
fn parse_frame(line: &str) -> Option<Frame> {
    let rest = line.strip_prefix('#')?;
    // Drop the frame number and the absolute address; neither is stable across boots.
    let mut parts = rest.split_whitespace();
    let _number: u32 = parts.next()?.parse().ok()?;
    let addr = parts.next()?;
    if !addr.starts_with("0x") {
        return None;
    }

    let tail = rest
        .split_once(addr)
        .map(|(_, tail)| tail.trim())
        .unwrap_or_default();

    // `symbol (module + 0xoffset)`, where either half may be missing or `n/a`.
    let (symbol, location) = match tail.split_once('(') {
        Some((symbol, location)) => (symbol.trim(), location.trim_end_matches(')').trim()),
        None => (tail, ""),
    };

    let function = match symbol {
        "" | "n/a" => None,
        other => Some(other.to_owned()),
    };

    let (module, module_offset) = match location.split_once('+') {
        Some((module, offset)) => {
            let offset = offset.trim().trim_start_matches("0x");
            (
                Some(module.trim().to_owned()),
                u64::from_str_radix(offset, 16).ok(),
            )
        }
        None if location.is_empty() => (None, None),
        None => (Some(location.to_owned()), None),
    };

    // A line that yielded nothing identifiable is still a frame: its position matters.
    Some(Frame {
        function,
        module: module.map(basename),
        module_offset,
    })
}

/// `/usr/lib/x86_64-linux-gnu/libc.so.6` -> `libc.so.6`, so a multiarch path change does not
/// alter the signature.
fn basename(path: String) -> String {
    match path.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name.to_owned(),
        _ => path,
    }
}

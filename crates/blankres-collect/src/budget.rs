//! Time and I/O budgets.
//!
//! Apport's real cost is not any single expensive operation, it is that every operation is
//! unbounded. Each collector here charges against a budget and gives up when it is spent, so a
//! pathological package or an enormous log cannot turn one crash into a stall.

use std::time::{Duration, Instant};

/// Why a collector stopped early.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Exhausted {
    #[error("time budget of {budget:?} exhausted")]
    Time { budget: Duration },
    #[error("read budget of {budget} bytes exhausted")]
    Bytes { budget: u64 },
}

/// A wall-clock and read-bytes allowance shared by the collectors of one report.
#[derive(Debug)]
pub struct Budget {
    started: Instant,
    time: Duration,
    bytes_allowed: u64,
    bytes_used: u64,
}

impl Budget {
    pub fn new(time: Duration, bytes: u64) -> Self {
        Self {
            started: Instant::now(),
            time,
            bytes_allowed: bytes,
            bytes_used: 0,
        }
    }

    /// Stage 1's allowance: milliseconds, and only what is already in the journal record.
    ///
    /// The byte allowance is not zero because reading `/etc/os-release` and the cached package
    /// index is legitimate; it is small enough that scanning anything is impossible.
    pub fn stage1() -> Self {
        Self::new(Duration::from_millis(50), 256 * 1024)
    }

    /// Stage 2's allowance. Generous by stage-1 standards, still bounded.
    pub fn stage2() -> Self {
        Self::new(Duration::from_secs(20), 64 * 1024 * 1024)
    }

    /// Check the clock before starting a unit of work.
    pub fn check_time(&self) -> Result<(), Exhausted> {
        if self.started.elapsed() > self.time {
            return Err(Exhausted::Time { budget: self.time });
        }
        Ok(())
    }

    /// Reserve `bytes` of reading. Charged before the read, so an oversized file is declined
    /// rather than read and then regretted.
    pub fn charge(&mut self, bytes: u64) -> Result<(), Exhausted> {
        self.check_time()?;
        if self.bytes_used + bytes > self.bytes_allowed {
            return Err(Exhausted::Bytes {
                budget: self.bytes_allowed,
            });
        }
        self.bytes_used += bytes;
        Ok(())
    }

    pub fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

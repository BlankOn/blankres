//! The crash as it arrives from the journal.
//!
//! `systemd-coredump` already attaches most of what apport scrapes out of `/proc` at crash time,
//! which is the whole reason the journal path is cheaper: by the time we look, the data has been
//! collected for us and the process has been reaped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Journal `MESSAGE_ID` for a systemd-coredump entry.
pub const COREDUMP_MESSAGE_ID: &str = "fc2e22bc6ee647b6b90729ab34a250b1";

/// One coredump journal entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoredumpRecord {
    /// `COREDUMP_*` fields, keyed without the prefix (`EXE`, `PID`, `SIGNAL`, ...).
    pub fields: BTreeMap<String, String>,
    /// The human-readable message, which carries the symbolized stack trace when systemd was
    /// built against libdw.
    pub message: String,
    /// Unix seconds, from the journal's realtime timestamp.
    pub timestamp: u64,
    /// Opaque journal cursor, persisted so a daemon restart resumes rather than replays.
    pub cursor: String,
}

impl CoredumpRecord {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    fn parsed<T: std::str::FromStr>(&self, name: &str) -> Option<T> {
        self.field(name)?.trim().parse().ok()
    }

    pub fn executable(&self) -> Option<&str> {
        self.field("EXE")
    }

    pub fn pid(&self) -> Option<u32> {
        self.parsed("PID")
    }

    pub fn uid(&self) -> Option<u32> {
        self.parsed("UID")
    }

    pub fn signal(&self) -> Option<u32> {
        // systemd writes either `11` or `11 (SIGSEGV)`.
        let raw = self.field("SIGNAL")?;
        raw.split_whitespace().next()?.parse().ok()
    }

    /// Path of the saved core dump. Absent when systemd is configured with `Storage=journal` or
    /// `Storage=none`, in which case stage 2 is impossible.
    pub fn core_path(&self) -> Option<PathBuf> {
        self.field("FILENAME").map(PathBuf::from)
    }

    pub fn command_line(&self) -> Option<&str> {
        self.field("CMDLINE")
    }

    pub fn environ(&self) -> Option<&str> {
        self.field("ENVIRON")
    }

    pub fn proc_maps(&self) -> Option<&str> {
        self.field("PROC_MAPS")
    }

    pub fn proc_status(&self) -> Option<&str> {
        self.field("PROC_STATUS")
    }

    /// Absolute paths of the file-backed objects mapped at crash time.
    ///
    /// This is the input to targeted integrity checking: these are the only files that could have
    /// contributed to the crash, so they are the only ones worth hashing.
    pub fn mapped_files(&self) -> Vec<PathBuf> {
        let Some(maps) = self.proc_maps() else {
            return Vec::new();
        };

        let mut seen = Vec::new();
        for line in maps.lines() {
            // `addr perms offset dev inode path`, path optional.
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            if !path.starts_with('/') {
                continue;
            }
            // Anonymous and device mappings are not package files.
            if path.starts_with("/dev/")
                || path.starts_with("/memfd:")
                || path.starts_with("/proc/")
                || path.ends_with("(deleted)")
            {
                continue;
            }
            let path = Path::new(path).to_path_buf();
            if !seen.contains(&path) {
                seen.push(path);
            }
        }

        seen
    }
}

/// Builder used by tests and by the journal sources.
#[derive(Debug, Default)]
pub struct RecordBuilder(CoredumpRecord);

impl RecordBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field(mut self, name: &str, value: impl Into<String>) -> Self {
        self.0.fields.insert(name.to_owned(), value.into());
        self
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.0.message = message.into();
        self
    }

    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.0.timestamp = timestamp;
        self
    }

    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.0.cursor = cursor.into();
        self
    }

    pub fn build(self) -> CoredumpRecord {
        self.0
    }
}

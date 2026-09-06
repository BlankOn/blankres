//! Reading crashes out of the journal.
//!
//! We consume `systemd-coredump`'s output rather than registering as the kernel's `core_pattern`
//! handler. That is the single most important decision in this project: the kernel keeps a dying
//! process pinned until its core-pattern handler drains the core, which is why apport blocks
//! restarting a crashed program for seconds. By the time a journal entry exists, systemd has
//! already written the core and the process has been reaped, so nothing we do here is on the
//! crash path at all.

use std::collections::BTreeMap;
use std::process::Stdio;

use blankres_collect::record::{CoredumpRecord, COREDUMP_MESSAGE_ID};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};

/// One journal entry, with its fields decoded to strings.
#[derive(Debug, Clone, Default)]
pub struct JournalEntry {
    pub fields: BTreeMap<String, String>,
    pub cursor: String,
    /// Unix seconds.
    pub timestamp: u64,
}

impl JournalEntry {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn message(&self) -> &str {
        self.get("MESSAGE").unwrap_or_default()
    }

    pub fn is_coredump(&self) -> bool {
        self.get("MESSAGE_ID") == Some(COREDUMP_MESSAGE_ID)
    }

    /// Reshape a coredump entry into the record the collectors consume.
    pub fn to_coredump_record(&self) -> CoredumpRecord {
        let fields = self
            .fields
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix("COREDUMP_")
                    .map(|name| (name.to_owned(), value.clone()))
            })
            .collect();

        CoredumpRecord {
            fields,
            message: self.message().to_owned(),
            timestamp: self.timestamp,
            cursor: self.cursor.clone(),
        }
    }
}

/// A source of journal entries.
///
/// A trait so the daemon's logic can be driven from fixtures in tests, and so an `sd-journal`
/// implementation can replace the subprocess one without touching anything above it.
#[allow(async_fn_in_trait)]
pub trait JournalSource {
    /// The next entry, or `None` when the source is finished.
    async fn next_entry(&mut self) -> Option<JournalEntry>;
}

/// Follows the journal by way of `journalctl -o json`.
///
/// A subprocess, but exactly one for the lifetime of the daemon rather than one per crash — the
/// cost apport pays. Matches are pushed down into `journalctl` so the kernel-oops watcher is not
/// woken for every log line on the system.
pub struct JournalctlSource {
    child: Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl JournalctlSource {
    /// Follow entries matching `matches`, resuming after `cursor` when one is known.
    pub fn spawn(matches: &[&str], cursor: Option<&str>) -> std::io::Result<Self> {
        let mut command = Command::new("journalctl");
        command
            .arg("--output=json")
            .arg("--follow")
            .arg("--no-pager");

        match cursor {
            // Resuming means crashes that happened while the daemon was down are still reported.
            Some(cursor) => {
                command.arg(format!("--after-cursor={cursor}"));
            }
            // With no cursor, start at the present rather than replaying the whole journal on
            // first install.
            None => {
                command.arg("--since=now");
            }
        }

        for match_arg in matches {
            command.arg(match_arg);
        }

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = child.stdout.take().expect("stdout was piped");
        Ok(Self {
            child,
            lines: BufReader::new(stdout).lines(),
        })
    }

    /// Follow systemd-coredump entries only.
    pub fn coredumps(cursor: Option<&str>) -> std::io::Result<Self> {
        Self::spawn(&[&format!("MESSAGE_ID={COREDUMP_MESSAGE_ID}")], cursor)
    }

    /// Follow kernel messages at error priority or worse, where oopses appear.
    pub fn kernel(cursor: Option<&str>) -> std::io::Result<Self> {
        Self::spawn(&["_TRANSPORT=kernel", "--priority=err"], cursor)
    }

    pub async fn shutdown(mut self) {
        let _ = self.child.kill().await;
    }
}

impl JournalSource for JournalctlSource {
    async fn next_entry(&mut self) -> Option<JournalEntry> {
        loop {
            let line = self.lines.next_line().await.ok().flatten()?;
            if line.trim().is_empty() {
                continue;
            }
            match parse_entry(&line) {
                Some(entry) => return Some(entry),
                None => {
                    tracing::debug!("skipping unparseable journal line");
                    continue;
                }
            }
        }
    }
}

/// Parse one line of `journalctl -o json`.
///
/// Fields that are not valid UTF-8 — which includes the NUL-separated `COREDUMP_CMDLINE` and
/// `COREDUMP_ENVIRON` we specifically want — arrive as arrays of byte values rather than strings,
/// so both shapes have to be handled or the most interesting fields silently vanish.
pub fn parse_entry(line: &str) -> Option<JournalEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;

    let mut fields = BTreeMap::new();
    for (key, value) in object {
        if let Some(text) = decode_field(value) {
            fields.insert(key.clone(), text);
        }
    }

    let cursor = fields.get("__CURSOR").cloned().unwrap_or_default();
    // Journal timestamps are microseconds since the epoch.
    let timestamp = fields
        .get("__REALTIME_TIMESTAMP")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|micros| micros / 1_000_000)
        .unwrap_or_else(now_secs);

    Some(JournalEntry {
        fields,
        cursor,
        timestamp,
    })
}

fn decode_field(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        // A byte array: journald's escape hatch for a field that is not valid UTF-8.
        serde_json::Value::Array(items) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|item| item.as_u64())
                .map(|byte| byte as u8)
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A source backed by a fixed list of entries, for tests.
pub struct FixtureSource {
    entries: std::collections::VecDeque<JournalEntry>,
}

impl FixtureSource {
    pub fn new(entries: Vec<JournalEntry>) -> Self {
        Self {
            entries: entries.into(),
        }
    }

    /// Build from raw `journalctl -o json` lines.
    pub fn from_lines(lines: &[&str]) -> Self {
        Self::new(lines.iter().filter_map(|line| parse_entry(line)).collect())
    }
}

impl JournalSource for FixtureSource {
    async fn next_entry(&mut self) -> Option<JournalEntry> {
        self.entries.pop_front()
    }
}

//! Persistent daemon state: journal cursor, per-signature counts, suppressions, rate limits.
//!
//! Small enough for a JSON file rewritten atomically. A database here would be its own liability
//! on a desktop, and the data is worthless if lost — worst case the daemon re-asks a question.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// How many events for one executable are allowed per window before suppression kicks in.
pub const RATE_LIMIT: u32 = 6;
/// Length of that window, in seconds.
pub const RATE_WINDOW_SECS: u64 = 3600;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureState {
    /// Crashes of this signature seen on this machine.
    #[serde(default)]
    pub count: u32,
    /// The user chose "never for this problem".
    #[serde(default)]
    pub declined: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// Where to resume the coredump journal.
    #[serde(default)]
    pub coredump_cursor: Option<String>,
    /// Where to resume the kernel journal.
    #[serde(default)]
    pub kernel_cursor: Option<String>,
    #[serde(default)]
    pub signatures: HashMap<String, SignatureState>,
    /// Recent event times per executable, for rate limiting.
    #[serde(default)]
    pub recent: HashMap<String, Vec<u64>>,
    /// Per-installation salt for the pseudonymous machine id. Never transmitted.
    #[serde(default)]
    pub machine_salt: Option<String>,
}

impl State {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Write atomically, so a power loss mid-write cannot leave an unparseable state file that
    /// would make the daemon replay the whole journal on next boot.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = temp_path(path);
        std::fs::write(&temp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&temp, path)
    }

    /// Record a crash and return its running count for this machine.
    pub fn note_signature(&mut self, hash: &str) -> u32 {
        let entry = self.signatures.entry(hash.to_owned()).or_default();
        entry.count += 1;
        entry.count
    }

    pub fn is_declined(&self, hash: &str) -> bool {
        self.signatures
            .get(hash)
            .map(|state| state.declined)
            .unwrap_or(false)
    }

    /// Remember that the user never wants to be asked about this problem again.
    pub fn decline(&mut self, hash: &str) {
        self.signatures.entry(hash.to_owned()).or_default().declined = true;
    }

    /// Charge one event against the executable's rate limit.
    ///
    /// Returns how many were already inside the window. Called *before* any collection, so a
    /// crash storm costs a vector push rather than a report.
    pub fn charge_rate_limit(&mut self, executable: &str, now: u64) -> u32 {
        let window = self.recent.entry(executable.to_owned()).or_default();
        window.retain(|seen| now.saturating_sub(*seen) < RATE_WINDOW_SECS);
        let seen = window.len() as u32;
        window.push(now);
        seen
    }

    /// The machine salt, generating one on first use.
    pub fn salt(&mut self) -> String {
        if let Some(salt) = &self.machine_salt {
            return salt.clone();
        }
        let salt = random_hex();
        self.machine_salt = Some(salt.clone());
        salt
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    PathBuf::from(temp)
}

/// 32 hex characters of entropy, read from the OS.
fn random_hex() -> String {
    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut file| {
            use std::io::Read as _;
            file.read_exact(&mut bytes)
        })
        .is_err()
    {
        // Falling back to the clock is weak, but a predictable salt only degrades pseudonymity;
        // it never breaks reporting, and refusing to run would be worse.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        bytes[..16].copy_from_slice(&nanos.to_le_bytes()[..16]);
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

//! Where pending payloads live, and who may read them.
//!
//! A pending report contains the crashed process's command line and environment, so the layout is
//! privacy-driven rather than convenient: each user gets their own directory under the crash
//! directory, owned by them and unreadable by anyone else. That also gives the desktop front end
//! somewhere it can write the user's decisions back, which a root-owned flat directory would not.

use std::path::{Path, PathBuf};

use blankres_report::report::PendingUpload;

/// Per-user subdirectory of the crash directory.
pub fn user_dir(crash_dir: &Path, uid: u32) -> PathBuf {
    crash_dir.join(uid.to_string())
}

/// Where a user's declined signatures are recorded.
pub fn declined_path(crash_dir: &Path, uid: u32) -> PathBuf {
    user_dir(crash_dir, uid).join("declined.json")
}

/// Create a user's directory with the right ownership and mode.
///
/// `0700` and owned by the user: nobody else on the machine can list, let alone read, another
/// user's crashes. The chown is best effort because only root can perform it, and an unprivileged
/// test run must not fail on that.
pub fn ensure_user_dir(crash_dir: &Path, uid: u32) -> std::io::Result<PathBuf> {
    let dir = user_dir(crash_dir, uid);
    std::fs::create_dir_all(&dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let _ = std::os::unix::fs::chown(&dir, Some(uid), None);
    }

    Ok(dir)
}

/// Write a pending payload for the user to review.
pub fn write_pending(crash_dir: &Path, pending: &PendingUpload) -> std::io::Result<PathBuf> {
    let uid = pending.report.uid.unwrap_or(0);
    let dir = ensure_user_dir(crash_dir, uid)?;
    let path = dir.join(pending.file_name());

    let temp = path.with_extension("tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(pending)?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o640))?;
        let _ = std::os::unix::fs::chown(&temp, Some(uid), None);
    }

    std::fs::rename(&temp, &path)?;
    Ok(path)
}

/// A pending report on disk.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub path: PathBuf,
    pub pending: PendingUpload,
}

impl PendingEntry {
    /// A short human label, e.g. `firefox`.
    pub fn program(&self) -> String {
        self.pending
            .report
            .event
            .executable
            .rsplit('/')
            .next()
            .unwrap_or("program")
            .to_owned()
    }

    /// Bytes that would be transferred if the user consents.
    pub fn transfer_size(&self) -> u64 {
        self.pending.report.transfer_size()
    }
}

/// Reads and removes pending reports for one user.
#[derive(Debug, Clone)]
pub struct PendingStore {
    crash_dir: PathBuf,
    uid: u32,
}

impl PendingStore {
    pub fn new(crash_dir: impl Into<PathBuf>, uid: u32) -> Self {
        Self {
            crash_dir: crash_dir.into(),
            uid,
        }
    }

    pub fn dir(&self) -> PathBuf {
        user_dir(&self.crash_dir, self.uid)
    }

    pub fn crash_dir(&self) -> &Path {
        &self.crash_dir
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Everything awaiting this user's decision, newest first.
    pub fn list(&self) -> Vec<PendingEntry> {
        let Ok(entries) = std::fs::read_dir(self.dir()) else {
            return Vec::new();
        };

        let mut out: Vec<PendingEntry> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "report"))
            .filter_map(|path| match read_pending(&path) {
                Ok(pending) => Some(PendingEntry { path, pending }),
                // Skipping is right, but doing it silently is not: an unreadable report would
                // otherwise present as "nothing to report", which is the one answer a user cannot
                // act on or even question.
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "ignoring a crash report that could not be read"
                    );
                    None
                }
            })
            .collect();

        out.sort_by_key(|entry| std::cmp::Reverse(entry.pending.written_at));
        out
    }

    pub fn load(&self, path: &Path) -> std::io::Result<PendingEntry> {
        let bytes = std::fs::read(path)?;
        let pending = serde_json::from_slice(&bytes)?;
        Ok(PendingEntry {
            path: path.to_path_buf(),
            pending,
        })
    }

    /// Remove a pending report once it has been dealt with.
    pub fn remove(&self, entry: &PendingEntry) {
        let _ = std::fs::remove_file(&entry.path);
    }

    /// Remove the core dump a pending report referenced.
    ///
    /// Called whether the user sent or discarded: once the decision is made the core has served
    /// its purpose, and leaving hundreds of megabytes behind is the disk cost this project exists
    /// to avoid.
    pub fn remove_core(&self, entry: &PendingEntry) {
        if let Some(blankres_report::report::Attachment::File { path, .. }) =
            entry.pending.report.core_dump()
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn read_pending(path: &Path) -> std::io::Result<PendingUpload> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Signatures the user never wants to be asked about again.
///
/// Stored in the user's own directory so the desktop front end, which runs unprivileged, can
/// record a decision that the root daemon will honour.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Declined {
    #[serde(default)]
    pub signatures: Vec<String>,
}

impl Declined {
    pub fn load(crash_dir: &Path, uid: u32) -> Self {
        std::fs::read(declined_path(crash_dir, uid))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn contains(&self, signature: &str) -> bool {
        self.signatures.iter().any(|s| s == signature)
    }

    pub fn add(&mut self, signature: impl Into<String>) {
        let signature = signature.into();
        if !self.contains(&signature) {
            self.signatures.push(signature);
        }
    }

    pub fn save(&self, crash_dir: &Path, uid: u32) -> std::io::Result<()> {
        ensure_user_dir(crash_dir, uid)?;
        let path = declined_path(crash_dir, uid);
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::chown(&temp, Some(uid), None);
        }
        std::fs::rename(&temp, &path)
    }
}

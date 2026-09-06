//! On-disk spool for stage-1 events that could not be sent.
//!
//! A laptop crashes on a train and reports when it reaches wifi. Without a spool those crashes are
//! simply lost, which biases the crash database towards whoever happens to be online.

use std::path::{Path, PathBuf};

use blankres_report::event::CrashEvent;

/// Cap on spooled events, so a machine that is offline for a month does not fill its own disk.
/// The oldest are dropped first: recent crashes describe the current state of the system.
pub const MAX_SPOOLED: usize = 256;

pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Persist an event for a later attempt.
    pub fn push(&self, event: &CrashEvent) -> std::io::Result<PathBuf> {
        self.trim()?;
        let path = self.dir.join(format!(
            "{}-{}.json",
            event.timestamp,
            &event.signature.hash[..16.min(event.signature.hash.len())]
        ));
        std::fs::write(&path, serde_json::to_vec(event)?)?;
        Ok(path)
    }

    /// Everything currently spooled, oldest first.
    pub fn drain_list(&self) -> std::io::Result<Vec<(PathBuf, CrashEvent)>> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        entries.sort();

        let mut out = Vec::new();
        for path in entries {
            match std::fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            {
                Some(event) => out.push((path, event)),
                // A corrupt spool file is not worth retrying forever.
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(out)
    }

    pub fn remove(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    pub fn len(&self) -> usize {
        std::fs::read_dir(&self.dir)
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop the oldest entries once the cap is reached.
    fn trim(&self) -> std::io::Result<()> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        if entries.len() < MAX_SPOOLED {
            return Ok(());
        }
        entries.sort();
        for path in entries.iter().take(entries.len() - MAX_SPOOLED + 1) {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }
}

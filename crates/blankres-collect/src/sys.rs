//! Thin seams over the filesystem and subprocess spawning.
//!
//! Everything that touches the outside world goes through these traits, for two reasons: tests can
//! run against fixtures with no root and no real crash, and the stage-1 budget can be *enforced*
//! rather than asserted — a fake runner that counts spawns proves the cheap path stays cheap.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Read-only filesystem access.
pub trait Filesystem: Send + Sync {
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn metadata_len(&self, path: &Path) -> io::Result<u64>;
    /// Entries of a directory, as full paths.
    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    /// Modification time as unix seconds, used for cache invalidation.
    fn modified_secs(&self, path: &Path) -> io::Result<u64>;
    fn exists(&self, path: &Path) -> bool {
        self.metadata_len(path).is_ok()
    }
    /// Read a file's raw bytes. Never called on core dumps: those are streamed at upload time.
    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>>;
}

/// The real filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealFs;

impl Filesystem for RealFs {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn metadata_len(&self, path: &Path) -> io::Result<u64> {
        Ok(std::fs::metadata(path)?.len())
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            entries.push(entry?.path());
        }
        entries.sort();
        Ok(entries)
    }

    fn modified_secs(&self, path: &Path) -> io::Result<u64> {
        let modified = std::fs::metadata(path)?.modified()?;
        Ok(modified
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0))
    }

    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

/// An in-memory filesystem for tests.
#[derive(Debug, Default, Clone)]
pub struct MemFs {
    files: BTreeMap<PathBuf, Vec<u8>>,
    mtimes: BTreeMap<PathBuf, u64>,
}

impl MemFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) -> &mut Self {
        self.files.insert(path.into(), content.into());
        self
    }

    pub fn set_mtime(&mut self, path: impl Into<PathBuf>, secs: u64) -> &mut Self {
        self.mtimes.insert(path.into(), secs);
        self
    }
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{}", path.display()))
}

impl Filesystem for MemFs {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        let bytes = self.files.get(path).ok_or_else(|| not_found(path))?;
        String::from_utf8(bytes.clone()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn metadata_len(&self, path: &Path) -> io::Result<u64> {
        self.files
            .get(path)
            .map(|b| b.len() as u64)
            .ok_or_else(|| not_found(path))
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let entries: Vec<PathBuf> = self
            .files
            .keys()
            .filter(|p| p.parent() == Some(path))
            .cloned()
            .collect();
        if entries.is_empty() && !self.files.keys().any(|p| p.starts_with(path)) {
            return Err(not_found(path));
        }
        Ok(entries)
    }

    fn modified_secs(&self, path: &Path) -> io::Result<u64> {
        self.mtimes
            .get(path)
            .copied()
            .or_else(|| self.files.contains_key(path).then_some(0))
            .ok_or_else(|| not_found(path))
    }

    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.files.get(path).cloned().ok_or_else(|| not_found(path))
    }
}

/// Spawning external commands.
///
/// Stage 1 must never reach this trait; stage 2 may. Keeping it as a seam is what lets the
/// "no subprocess on the cheap path" rule be a test rather than a comment.
pub trait ProcessRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String>;
    /// How many spawns have happened. Real implementations count too, so the daemon can log it.
    fn spawn_count(&self) -> usize;
}

/// Runs real commands.
#[derive(Debug, Default)]
pub struct RealRunner {
    spawns: AtomicUsize,
}

impl ProcessRunner for RealRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
        let output = std::process::Command::new(program).args(args).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{program} exited with {}",
                output.status
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::Relaxed)
    }
}

/// A runner that refuses to spawn, for asserting that a code path is spawn-free.
#[derive(Debug, Default)]
pub struct NoSpawnRunner {
    attempts: AtomicUsize,
}

impl ProcessRunner for NoSpawnRunner {
    fn run(&self, program: &str, _args: &[&str]) -> io::Result<String> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(io::Error::other(format!(
            "spawning {program} is not allowed on this path"
        )))
    }

    fn spawn_count(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }
}

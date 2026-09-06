//! Package identification and integrity checking, dpkg flavour.
//!
//! Two deliberate departures from apport, both aimed at the I/O cost:
//!
//! * Path lookup goes through an index built once from `/var/lib/dpkg/info/*.list`, instead of
//!   forking `dpkg-query -S` per lookup.
//! * Integrity checking hashes only the files handed to it — the executable and the libraries
//!   actually mapped at crash time — instead of `dpkg --verify`, which md5sums every file in the
//!   package.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use blankres_report::event::PackageInfo;
use blankres_report::report::ModifiedFile;
use md5::{Digest as _, Md5};

use crate::sys::Filesystem;

/// Where dpkg keeps its per-package file lists and checksums.
pub const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";
/// The file whose mtime tells us the index is stale.
pub const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// Identify packages and verify their files.
pub trait PackageBackend: Send + Sync {
    /// Which package owns this path, if any.
    fn owner(&self, path: &Path) -> Option<PackageInfo>;
    /// Check the given paths against their recorded checksums.
    fn verify(&self, paths: &[PathBuf]) -> Vec<ModifiedFile>;
}

/// A path -> package index over dpkg's file lists.
#[derive(Debug, Default, Clone)]
pub struct DpkgIndex {
    paths: HashMap<PathBuf, String>,
    /// mtime of `status` when the index was built.
    built_from_status_mtime: u64,
}

impl DpkgIndex {
    /// Build the index by reading every `*.list` under `info_dir`.
    ///
    /// This is the one expensive operation in the package backend, so it happens once at daemon
    /// start rather than per crash.
    pub fn build<F: Filesystem>(fs: &F, info_dir: &Path, status: &Path) -> Self {
        let mut paths = HashMap::new();

        let entries = fs.list_dir(info_dir).unwrap_or_default();
        for entry in entries {
            let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(package) = name.strip_suffix(".list") else {
                continue;
            };
            // `foo:amd64.list` belongs to package `foo`.
            let package = package.split(':').next().unwrap_or(package).to_owned();

            let Ok(list) = fs.read_to_string(&entry) else {
                continue;
            };
            for line in list.lines() {
                let line = line.trim();
                if line.is_empty() || line == "/." {
                    continue;
                }
                // Directories are shared between packages and are never a crash's executable, so
                // last-writer-wins on them is harmless; files are unique to one package.
                paths.insert(PathBuf::from(line), package.clone());
            }
        }

        let built_from_status_mtime = fs.modified_secs(status).unwrap_or(0);

        Self {
            paths,
            built_from_status_mtime,
        }
    }

    /// Build against the real dpkg locations.
    pub fn build_default<F: Filesystem>(fs: &F) -> Self {
        Self::build(fs, Path::new(DPKG_INFO_DIR), Path::new(DPKG_STATUS))
    }

    /// True when dpkg has run since the index was built.
    pub fn is_stale<F: Filesystem>(&self, fs: &F, status: &Path) -> bool {
        fs.modified_secs(status)
            .map(|mtime| mtime != self.built_from_status_mtime)
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn package_of(&self, path: &Path) -> Option<&str> {
        self.paths.get(path).map(String::as_str)
    }
}

/// The dpkg implementation of [`PackageBackend`].
pub struct DpkgBackend<F: Filesystem> {
    fs: F,
    index: DpkgIndex,
    info_dir: PathBuf,
    /// Parsed once from `/var/lib/dpkg/status`: package -> (version, source).
    versions: HashMap<String, (Option<String>, Option<String>)>,
}

impl<F: Filesystem> DpkgBackend<F> {
    pub fn new(fs: F, index: DpkgIndex, info_dir: impl Into<PathBuf>, status: &Path) -> Self {
        let versions = parse_status(&fs, status);
        Self {
            fs,
            index,
            info_dir: info_dir.into(),
            versions,
        }
    }

    /// Construct against the real dpkg locations.
    pub fn with_defaults(fs: F) -> Self {
        let index = DpkgIndex::build_default(&fs);
        Self::new(fs, index, DPKG_INFO_DIR, Path::new(DPKG_STATUS))
    }

    /// Recorded md5sums for a package: path -> digest.
    fn md5sums(&self, package: &str) -> HashMap<PathBuf, String> {
        // dpkg writes either `foo.md5sums` or `foo:arch.md5sums`; try the plain name first.
        let candidates = [
            self.info_dir.join(format!("{package}.md5sums")),
            self.info_dir.join(format!("{package}:amd64.md5sums")),
        ];

        for candidate in candidates {
            let Ok(content) = self.fs.read_to_string(&candidate) else {
                continue;
            };
            return content
                .lines()
                .filter_map(|line| line.split_once("  "))
                .map(|(digest, path)| {
                    (
                        PathBuf::from(format!("/{}", path.trim())),
                        digest.to_owned(),
                    )
                })
                .collect();
        }

        HashMap::new()
    }
}

impl<F: Filesystem> PackageBackend for DpkgBackend<F> {
    fn owner(&self, path: &Path) -> Option<PackageInfo> {
        let package = self.index.package_of(path)?;
        let (version, source) = self.versions.get(package).cloned().unwrap_or((None, None));
        Some(PackageInfo {
            name: Some(package.to_owned()),
            version,
            source,
        })
    }

    /// Hash only the paths given, and only those dpkg has a checksum for.
    ///
    /// A file dpkg does not track cannot be judged modified, and reporting it as such would
    /// slander every locally built library.
    fn verify(&self, paths: &[PathBuf]) -> Vec<ModifiedFile> {
        let mut modified = Vec::new();
        // Group by package so each md5sums file is read once even for many mapped libraries.
        let mut by_package: HashMap<&str, Vec<&PathBuf>> = HashMap::new();
        for path in paths {
            if let Some(package) = self.index.package_of(path) {
                by_package.entry(package).or_default().push(path);
            }
        }

        for (package, paths) in by_package {
            let sums = self.md5sums(package);
            if sums.is_empty() {
                continue;
            }
            for path in paths {
                let Some(expected) = sums.get(path.as_path()) else {
                    continue;
                };
                let Ok(bytes) = self.fs.read_bytes(path) else {
                    continue;
                };
                let actual = hex::encode(Md5::digest(&bytes));
                if &actual != expected {
                    modified.push(ModifiedFile {
                        path: path.clone(),
                        package: package.to_owned(),
                    });
                }
            }
        }

        modified.sort_by(|a, b| a.path.cmp(&b.path));
        modified
    }
}

/// Parse `Package`/`Version`/`Source` triples out of `/var/lib/dpkg/status`.
fn parse_status<F: Filesystem>(
    fs: &F,
    status: &Path,
) -> HashMap<String, (Option<String>, Option<String>)> {
    let Ok(content) = fs.read_to_string(status) else {
        return HashMap::new();
    };

    let mut out = HashMap::new();
    let mut package = None;
    let mut version = None;
    let mut source = None;

    let flush = |package: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>,
                 out: &mut HashMap<String, (Option<String>, Option<String>)>| {
        if let Some(name) = package.take() {
            out.insert(name, (version.take(), source.take()));
        }
        *version = None;
        *source = None;
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            flush(&mut package, &mut version, &mut source, &mut out);
            continue;
        }
        if let Some(value) = line.strip_prefix("Package: ") {
            package = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("Version: ") {
            version = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("Source: ") {
            // `Source: foo (1.2-3)` — the version in parentheses is the source version.
            source = Some(
                value
                    .split_whitespace()
                    .next()
                    .unwrap_or(value)
                    .trim()
                    .to_owned(),
            );
        }
    }
    flush(&mut package, &mut version, &mut source, &mut out);

    out
}

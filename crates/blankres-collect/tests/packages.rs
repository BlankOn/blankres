//! The dpkg backend: index-based lookup, and verification that touches only what it is given.

mod common;

use blankres_collect::pkg::{DpkgIndex, PackageBackend};
use blankres_collect::sys::MemFs;
use std::path::{Path, PathBuf};

#[test]
fn resolves_an_executable_to_its_package_and_version() {
    let backend = common::backend(common::dpkg_fs());
    let info = backend.owner(Path::new("/usr/bin/foo")).expect("owned");
    assert_eq!(info.name.as_deref(), Some("foo"));
    assert_eq!(info.version.as_deref(), Some("1.0-1"));
    // `Source: foo-src (1.0)` — the version in parentheses is not part of the source name.
    assert_eq!(info.source.as_deref(), Some("foo-src"));
}

#[test]
fn strips_the_architecture_qualifier_from_list_filenames() {
    let backend = common::backend(common::dpkg_fs());
    let info = backend
        .owner(Path::new("/usr/lib/x86_64-linux-gnu/libc.so.6"))
        .expect("owned");
    assert_eq!(info.name.as_deref(), Some("libc6"));
    assert_eq!(info.version.as_deref(), Some("2.39-0ubuntu8"));
}

#[test]
fn an_unowned_path_has_no_package() {
    let backend = common::backend(common::dpkg_fs());
    assert!(backend
        .owner(Path::new("/usr/local/bin/hand-built"))
        .is_none());
}

#[test]
fn detects_a_modified_package_file() {
    let mut fs = common::dpkg_fs();
    fs.insert("/usr/bin/foo", "tampered\n");
    let backend = common::backend(fs);
    let modified = backend.verify(&[PathBuf::from("/usr/bin/foo")]);
    assert_eq!(modified.len(), 1);
    assert_eq!(modified[0].package, "foo");
}

#[test]
fn an_intact_file_is_not_reported_as_modified() {
    // The fixture's md5sums entry is the real digest of the file's contents.
    let backend = common::backend(common::dpkg_fs());
    assert!(backend.verify(&[PathBuf::from("/usr/bin/foo")]).is_empty());
}

#[test]
fn a_file_dpkg_does_not_track_is_never_called_modified() {
    // libc6 has no md5sums file in the fixture; claiming it changed would be a false accusation.
    let backend = common::backend(common::dpkg_fs());
    let modified = backend.verify(&[PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6")]);
    assert!(modified.is_empty());
}

#[test]
fn the_index_notices_when_dpkg_has_run() {
    let mut fs = common::dpkg_fs();
    fs.set_mtime(common::STATUS, 1000);
    let index = DpkgIndex::build(&fs, Path::new(common::INFO_DIR), Path::new(common::STATUS));
    assert!(!index.is_stale(&fs, Path::new(common::STATUS)));

    let mut after_upgrade = fs.clone();
    after_upgrade.set_mtime(common::STATUS, 2000);
    assert!(index.is_stale(&after_upgrade, Path::new(common::STATUS)));
}

#[test]
fn an_empty_dpkg_tree_yields_an_empty_index_rather_than_failing() {
    let fs = MemFs::new();
    let index = DpkgIndex::build(&fs, Path::new("/nowhere"), Path::new("/nowhere/status"));
    assert!(index.is_empty());
}

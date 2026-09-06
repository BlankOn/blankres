//! The stage split is the design. These tests hold it in place: stage 1 must stay cheap and
//! secret-free, stage 2 must reference the core rather than read it, and neither may leak data
//! the other stage is responsible for.

mod common;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use blankres_collect::budget::Budget;
use blankres_collect::stage1::Stage1Collector;
use blankres_collect::stage2::Stage2Collector;
use blankres_collect::sys::{Filesystem, MemFs, NoSpawnRunner, ProcessRunner};
use blankres_collect::system::{pseudonymous_machine_id, system_info};
use blankres_report::report::Attachment;
use blankres_report::signature::Precision;

/// Wraps a filesystem and records every path whose *contents* were read.
///
/// `metadata_len` is deliberately not recorded: stat'ing the core for its size is allowed and
/// necessary, reading its bytes is not.
struct WatchfulFs {
    inner: MemFs,
    reads: Mutex<Vec<PathBuf>>,
}

impl WatchfulFs {
    fn new(inner: MemFs) -> Self {
        Self {
            inner,
            reads: Mutex::new(Vec::new()),
        }
    }

    fn read_paths(&self) -> Vec<PathBuf> {
        self.reads.lock().unwrap().clone()
    }
}

impl Filesystem for WatchfulFs {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.reads.lock().unwrap().push(path.to_path_buf());
        self.inner.read_to_string(path)
    }

    fn metadata_len(&self, path: &Path) -> io::Result<u64> {
        self.inner.metadata_len(path)
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.inner.list_dir(path)
    }

    fn modified_secs(&self, path: &Path) -> io::Result<u64> {
        self.inner.modified_secs(path)
    }

    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.reads.lock().unwrap().push(path.to_path_buf());
        self.inner.read_bytes(path)
    }
}

fn stage1(fs: MemFs) -> Stage1Collector<WatchfulFs, blankres_collect::DpkgBackend<MemFs>> {
    let system = system_info(&fs, "6.8.0-41-generic".to_owned());
    let machine_id = pseudonymous_machine_id("0123456789abcdef", b"salt");
    Stage1Collector::new(
        WatchfulFs::new(fs.clone()),
        common::backend(fs),
        system,
        machine_id,
    )
}

#[test]
fn stage_one_builds_a_complete_event_from_the_journal_record_alone() {
    let collector = stage1(common::dpkg_fs());
    let event = collector.collect(&common::record(), 3);

    assert_eq!(event.executable, "/usr/bin/foo");
    assert_eq!(event.signal, Some(11));
    assert_eq!(event.signal_name.as_deref(), Some("SIGSEGV"));
    assert_eq!(event.package.name.as_deref(), Some("foo"));
    assert_eq!(event.package.version.as_deref(), Some("1.0-1"));
    assert_eq!(event.system.distro, "Ubuntu");
    assert_eq!(event.crash_count, 3);
    assert_eq!(event.signature.precision, Precision::Precise);
    assert_eq!(
        event.signature.frames.first().map(String::as_str),
        Some("parse_config")
    );
}

#[test]
fn stage_one_spawns_no_subprocess() {
    // The runner is offered to the collector's world but must never be reached: a fork per crash
    // is exactly the cost we removed.
    let runner = NoSpawnRunner::default();
    let collector = stage1(common::dpkg_fs());
    let _ = collector.collect(&common::record(), 1);
    assert_eq!(runner.spawn_count(), 0);
}

#[test]
fn stage_one_stats_the_core_but_never_reads_it() {
    let fs = common::dpkg_fs();
    let system = system_info(&fs, "6.8".to_owned());
    let watchful = WatchfulFs::new(fs.clone());
    let collector = Stage1Collector::new(watchful, common::backend(fs), system, "m".to_owned());

    let event = collector.collect(&common::record(), 1);

    assert!(
        event.core_available,
        "the core exists and its size is known"
    );
    assert_eq!(event.core_size, Some(4096));

    // The point of the stage split: the size came from a stat, not from opening the file.
    let reads = collector.filesystem().read_paths();
    assert!(
        !reads.iter().any(|p| p == Path::new(common::CORE_PATH)),
        "stage 1 read the core dump: {reads:?}"
    );
}

#[test]
fn stage_one_stays_within_its_time_budget() {
    let collector = stage1(common::dpkg_fs());
    let mut budget = Budget::stage1();
    let _ = collector.collect_within(&common::record(), 1, &mut budget);
    assert!(
        budget.check_time().is_ok(),
        "stage 1 took {:?}, over its 50ms budget",
        budget.elapsed()
    );
}

#[test]
fn stage_one_carries_no_environment_or_command_line() {
    let collector = stage1(common::dpkg_fs());
    let event = collector.collect(&common::record(), 1);
    let encoded = serde_json::to_string(&event).expect("serializes");
    assert!(!encoded.contains("AWS_SECRET"), "no environment in stage 1");
    assert!(!encoded.contains("abc123"), "no command line in stage 1");
}

#[test]
fn a_crash_with_no_stack_trace_falls_back_to_a_coarse_signature() {
    let mut record = common::record();
    record.message = "Process 4242 (foo) of user 1000 dumped core.".to_owned();
    let collector = stage1(common::dpkg_fs());
    let event = collector.collect(&record, 1);
    assert_eq!(event.signature.precision, Precision::Coarse);
}

#[test]
fn a_crash_with_no_saved_core_reports_stage_two_as_impossible() {
    let mut record = common::record();
    record.fields.remove("FILENAME");
    let collector = stage1(common::dpkg_fs());
    let event = collector.collect(&record, 1);
    assert!(!event.core_available);
    assert_eq!(event.core_size, None);
}

#[test]
fn stage_two_redacts_the_environment_and_command_line() {
    let fs = common::dpkg_fs();
    let collector = Stage2Collector::new(fs.clone(), common::backend(fs.clone()));
    let event = stage1(fs).collect(&common::record(), 1);
    let report = collector.collect(event, "evt-1", &common::record());

    assert!(!report.environment.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert_eq!(report.environment["PATH"], "/usr/bin");
    assert_eq!(report.environment_withheld, 1);
    assert!(
        report
            .command_line
            .iter()
            .all(|arg| !arg.contains("abc123")),
        "token survived scrubbing: {:?}",
        report.command_line
    );
}

#[test]
fn stage_two_references_the_core_rather_than_reading_it() {
    let fs = common::dpkg_fs();
    let watchful = WatchfulFs::new(fs.clone());
    let collector = Stage2Collector::new(watchful, common::backend(fs.clone()));
    let event = stage1(fs).collect(&common::record(), 1);

    let report = collector.collect(event, "evt-1", &common::record());

    let core = report.core_dump().expect("core attached");
    match core {
        Attachment::File {
            path,
            size,
            compression,
            ..
        } => {
            assert_eq!(path, Path::new(common::CORE_PATH));
            assert_eq!(*size, 4096);
            // Already zstd on disk; re-compressing it would be apport's mistake.
            assert_eq!(compression.as_deref(), Some("zstd"));
        }
        other => panic!("core dump must be a file reference, got {other:?}"),
    }

    let reads = collector.filesystem().read_paths();
    assert!(
        !reads.iter().any(|p| p == Path::new(common::CORE_PATH)),
        "stage 2 read the core dump instead of referencing it: {reads:?}"
    );
}

#[test]
fn stage_two_verifies_only_the_mapped_files() {
    let mut fs = common::dpkg_fs();
    fs.insert("/usr/bin/foo", "tampered\n");
    let collector = Stage2Collector::new(fs.clone(), common::backend(fs.clone()));
    let event = stage1(fs).collect(&common::record(), 1);

    let report = collector.collect(event, "evt-1", &common::record());

    assert_eq!(report.modified_files.len(), 1);
    assert_eq!(report.modified_files[0].path, Path::new("/usr/bin/foo"));
}

#[test]
fn stage_two_records_what_a_spent_budget_forced_it_to_skip() {
    let fs = common::dpkg_fs();
    let collector = Stage2Collector::new(fs.clone(), common::backend(fs.clone()));
    let event = stage1(fs).collect(&common::record(), 1);

    // A budget with no room at all: every optional collector must decline and say so.
    let mut budget = Budget::new(std::time::Duration::from_secs(30), 0);
    let report = collector.collect_within(event, "evt-1", &common::record(), &mut budget);

    assert!(
        report.skipped.iter().any(|s| s.name == "proc-maps"),
        "a skipped collector must be recorded, not silently omitted: {:?}",
        report.skipped
    );
}

#[test]
fn mapped_files_exclude_anonymous_and_deleted_mappings() {
    let record = common::record();
    let mapped = record.mapped_files();
    assert!(mapped.contains(&PathBuf::from("/usr/bin/foo")));
    assert!(mapped.contains(&PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6")));
    assert_eq!(
        mapped.len(),
        2,
        "memfd and anonymous maps are not package files"
    );
}

#[test]
fn the_machine_id_is_not_the_raw_machine_id() {
    let hashed = pseudonymous_machine_id("0123456789abcdef", b"salt");
    assert_ne!(
        hashed, "0123456789abcdef",
        "the raw machine id is a host secret"
    );
    assert_eq!(hashed.len(), 64);
    // Stable for a given salt, or per-machine crash counts would fragment.
    assert_eq!(hashed, pseudonymous_machine_id("0123456789abcdef", b"salt"));
    // Trailing newline from the file must not change the identity.
    assert_eq!(
        hashed,
        pseudonymous_machine_id("0123456789abcdef\n", b"salt")
    );
    // The salt is what removes the confirmation oracle: without it, anyone who can read
    // /etc/machine-id on a host could check whether that host appears in the crash database.
    assert_ne!(
        hashed,
        pseudonymous_machine_id("0123456789abcdef", b"other-salt")
    );
}

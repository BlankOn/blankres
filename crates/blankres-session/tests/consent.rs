//! The consent layer. These cover what both front ends actually invoke when a button is pressed,
//! so the CLI and the GTK window cannot drift apart in what they promise the user.

use blankres_i18n::{Catalog, Lang};
use blankres_report::event::{CrashEvent, PackageInfo, PayloadDirective, ReportKind, SystemInfo};
use blankres_report::report::{Attachment, PendingUpload, Report, CORE_DUMP_ATTACHMENT};
use blankres_report::signature::{Precision, Signature};
use blankres_session::{
    human_size, now_secs, write_pending, Declined, PendingStore, ReportSession,
};

const UID: u32 = 1000;

/// Assertions here are on English text, so the ambient locale must not decide the outcome.
fn english() -> Catalog {
    Catalog::new(Lang::English)
}

fn pending(core: &std::path::Path, expires_in: i64) -> PendingUpload {
    let now = now_secs();
    PendingUpload {
        report: Report {
            event: CrashEvent {
                schema: 1,
                signature: Signature {
                    hash: "a".repeat(64),
                    precision: Precision::Precise,
                    frames: vec!["parse_config".to_owned()],
                },
                kind: ReportKind::NativeCrash,
                timestamp: now,
                executable: "/usr/lib/firefox/firefox".to_owned(),
                signal: Some(11),
                signal_name: Some("SIGSEGV".to_owned()),
                package: PackageInfo {
                    name: Some("firefox".to_owned()),
                    version: Some("128.0".to_owned()),
                    source: Some("firefox".to_owned()),
                },
                system: SystemInfo {
                    distro: "Debian GNU/Linux".to_owned(),
                    distro_version: "14".to_owned(),
                    architecture: "x86_64".to_owned(),
                    kernel_version: "6.8.0".to_owned(),
                },
                machine_id: "m".repeat(64),
                crash_count: 1,
                client_version: "0.1.0".to_owned(),
                core_available: true,
                core_size: Some(4096),
            },
            directive_id: "evt-1".to_owned(),
            command_line: vec!["/usr/lib/firefox/firefox".to_owned()],
            environment: [("LANG".to_owned(), "en_US.UTF-8".to_owned())].into(),
            environment_withheld: 37,
            uid: Some(UID),
            stack_trace: Vec::new(),
            modified_files: Vec::new(),
            attachments: vec![Attachment::File {
                name: CORE_DUMP_ATTACHMENT.to_owned(),
                path: core.to_path_buf(),
                size: 4096,
                compression: Some("zstd".to_owned()),
            }],
            skipped: Vec::new(),
        },
        directive: PayloadDirective {
            id: "evt-1".to_owned(),
            need_payload: true,
            upload_token: Some("t".repeat(64)),
            max_bytes: Some(1024 * 1024),
            expires_at: Some((now as i64 + expires_in) as u64),
        },
        written_at: now,
        awaiting_directive: false,
    }
}

/// A crash directory containing one pending report and its core.
fn fixture(expires_in: i64) -> (tempfile::TempDir, PendingStore, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let crash_dir = dir.path().join("crash");
    let core = dir.path().join("core.zst");
    std::fs::write(&core, vec![0u8; 4096]).expect("write core");

    write_pending(&crash_dir, &pending(&core, expires_in)).expect("write pending");
    let store = PendingStore::new(&crash_dir, UID);
    (dir, store, core)
}

#[test]
fn a_pending_report_is_listed_for_its_own_user() {
    let (_dir, store, _core) = fixture(3600);
    let entries = store.list();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].program(), "firefox");
    assert_eq!(entries[0].transfer_size(), 4096);
}

#[test]
fn another_users_reports_are_not_listed() {
    let (_dir, store, _core) = fixture(3600);
    // The same crash directory, a different uid: the layout must not leak across users.
    let other = PendingStore::new(store.crash_dir(), UID + 1);
    assert!(other.list().is_empty());
}

#[test]
fn the_disclosure_names_every_field_that_would_be_sent() {
    let (_dir, store, _core) = fixture(3600);
    let entry = store.list().remove(0);
    let session = ReportSession::with_catalog(&store, entry, english());
    let rows = session.disclosure();

    let labels: Vec<&str> = rows.iter().map(|(label, _)| label.as_str()).collect();
    for expected in [
        "Program",
        "Signal",
        "Package",
        "Kernel",
        "Crash signature",
        "Command line",
    ] {
        assert!(
            labels.contains(&expected),
            "missing {expected} from {labels:?}"
        );
    }

    // The user must be told the environment was filtered, not shown a partial one as if complete.
    assert!(
        rows.iter()
            .any(|(_, value)| value.contains("37 more variables withheld")),
        "withheld variables must be disclosed"
    );

    // And the core must be described as what it is.
    assert!(
        rows.iter().any(|(label, value)| label.contains("core-dump")
            && value.contains("snapshot of the program's memory")),
        "the core dump must be described in plain language: {rows:?}"
    );
}

#[test]
fn the_transfer_summary_states_the_size() {
    let (_dir, store, _core) = fixture(3600);
    let session = ReportSession::with_catalog(&store, store.list().remove(0), english());
    assert_eq!(session.transfer_summary(), "Includes 4.0 KB");
}

#[test]
fn discarding_removes_both_the_report_and_the_core() {
    let (_dir, store, core) = fixture(3600);
    let entry = store.list().remove(0);
    let path = entry.path.clone();

    ReportSession::with_catalog(&store, entry, english()).discard();

    assert!(!path.exists(), "the report file must be gone");
    assert!(
        !core.exists(),
        "the core must be reclaimed, not left behind like apport does"
    );
    assert!(store.list().is_empty());
}

#[test]
fn declining_forever_records_the_signature_for_the_daemon() {
    let (_dir, store, core) = fixture(3600);
    let entry = store.list().remove(0);
    let signature = entry.pending.report.event.signature.hash.clone();

    ReportSession::with_catalog(&store, entry, english())
        .decline_forever()
        .expect("records the decision");

    // The desktop front end runs unprivileged, so the decision has to land somewhere the root
    // daemon will read it.
    let declined = Declined::load(store.crash_dir(), UID);
    assert!(declined.contains(&signature));
    assert!(!core.exists());
    assert!(store.list().is_empty());
}

#[test]
fn declining_twice_does_not_duplicate_the_entry() {
    let (_dir, store, _core) = fixture(3600);
    let mut declined = Declined::load(store.crash_dir(), UID);
    declined.add("abc");
    declined.add("abc");
    declined.save(store.crash_dir(), UID).expect("saved");
    assert_eq!(Declined::load(store.crash_dir(), UID).signatures.len(), 1);
}

#[tokio::test]
async fn an_expired_report_refuses_to_upload() {
    // The server issued a time-limited capability; sending after it lapses would only waste the
    // user's bandwidth on a payload that gets rejected.
    let (_dir, store, core) = fixture(-10);
    let entry = store.list().remove(0);
    let session = ReportSession::with_catalog(&store, entry, english());

    assert!(!session.is_actionable(now_secs()));

    let client = blankres_client::Client::new(blankres_client::Endpoint::new(
        "http://127.0.0.1:1",
        "token",
    ))
    .expect("client");
    let err = session.send(&client).await.expect_err("must refuse");
    assert!(
        matches!(err, blankres_session::SessionError::Expired),
        "{err}"
    );

    // And it must not have destroyed the evidence on the way out.
    assert!(core.exists());
}

#[test]
fn sizes_are_rendered_the_way_a_person_would_say_them() {
    assert_eq!(human_size(512), "512 B");
    assert_eq!(human_size(4096), "4.0 KB");
    assert_eq!(human_size(412 * 1024 * 1024), "412.0 MB");
}

#[test]
fn a_pending_report_file_is_named_for_its_program_and_user() {
    let (_dir, store, _core) = fixture(3600);
    let entry = store.list().remove(0);
    let name = entry
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(name, "usr_lib_firefox_firefox.1000.report");
}

/// A report written while the server was unreachable: no upload token yet.
fn unconfirmed(core: &std::path::Path) -> PendingUpload {
    let mut pending = pending(core, 3600);
    pending.awaiting_directive = true;
    pending.directive = blankres_report::event::PayloadDirective {
        id: String::new(),
        need_payload: true,
        upload_token: None,
        max_bytes: None,
        expires_at: None,
    };
    pending
}

#[test]
fn a_report_awaiting_a_directive_is_still_actionable() {
    // It has no upload token and no deadline, and it must still be offerable to the user: the
    // whole point is that a crash which could not be reported is not hidden from them.
    let dir = tempfile::tempdir().expect("temp dir");
    let crash_dir = dir.path().join("crash");
    let core = dir.path().join("core.zst");
    std::fs::write(&core, vec![0u8; 4096]).expect("write core");
    write_pending(&crash_dir, &unconfirmed(&core)).expect("write pending");

    let store = PendingStore::new(&crash_dir, UID);
    let entry = store.list().remove(0);
    let session = ReportSession::with_catalog(&store, entry, english());

    assert!(session.is_actionable(now_secs()));
}

#[tokio::test]
async fn sending_an_unconfirmed_report_needs_the_server() {
    // Without a token there is nothing to upload against, so an unreachable server must surface
    // as a failure the user can retry, not as a silent success.
    let dir = tempfile::tempdir().expect("temp dir");
    let crash_dir = dir.path().join("crash");
    let core = dir.path().join("core.zst");
    std::fs::write(&core, vec![0u8; 4096]).expect("write core");
    write_pending(&crash_dir, &unconfirmed(&core)).expect("write pending");

    let store = PendingStore::new(&crash_dir, UID);
    let entry = store.list().remove(0);
    let session = ReportSession::with_catalog(&store, entry, english());

    let client = blankres_client::Client::new(blankres_client::Endpoint::new(
        "http://127.0.0.1:1",
        "token",
    ))
    .expect("client");

    let err = session.send(&client).await.expect_err("must fail");
    assert!(
        matches!(err, blankres_session::SessionError::Upload(_)),
        "{err}"
    );
    // Nothing was destroyed, so the user can try again later.
    assert!(core.exists());
    assert_eq!(store.list().len(), 1);
}

//! The daemon's decision loop against a real ingest server.
//!
//! This is where the two-stage design is actually visible: the same crash either ends at stage 1
//! with the core deleted, or produces a pending payload awaiting consent, depending entirely on
//! what the server answered. Needs `BLANKRES_TEST_DATABASE_URL`; skips without it.

use std::path::Path;

use blankres_client::{Client, Endpoint};
use blankres_collect::pkg::{DpkgBackend, DpkgIndex};
use blankres_collect::record::{CoredumpRecord, RecordBuilder};
use blankres_collect::stage1::Stage1Collector;
use blankres_collect::stage2::Stage2Collector;
use blankres_collect::sys::RealFs;
use blankres_collect::system::system_info;
use blankres_daemon::config::ClientConfig;
use blankres_daemon::reporter::{Outcome, Reporter};
use blankres_daemon::spool::Spool;
use blankres_daemon::state::{State, RATE_LIMIT};
use blankres_report::report::PendingUpload;
use blankres_server::config::hash_token;

const TOKEN: &str = "daemon-test-token";

fn database_url() -> Option<String> {
    std::env::var("BLANKRES_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
}

async fn start_server(quota: i64, storage: &Path) -> Option<String> {
    let config = blankres_server::Config {
        bind: "127.0.0.1:0".to_owned(),
        database_url: database_url()?,
        storage_root: storage.to_path_buf(),
        token_hashes: vec![hash_token(TOKEN)],
        payloads_per_signature: quota,
        max_payload_bytes: 64 * 1024 * 1024,
        upload_token_ttl_secs: 300,
        public_url: None,
    };
    let app = blankres_server::build(config).await.expect("server builds");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Some(format!("http://{address}"))
}

/// A crash of a real, unique executable path, with a real core file on disk.
fn record(dir: &Path, tag: &str) -> (CoredumpRecord, std::path::PathBuf) {
    let exe = format!("/usr/bin/{tag}");
    let core = dir.join(format!("{tag}.core.zst"));
    std::fs::write(&core, vec![0xAB; 8192]).expect("write core");

    let record = RecordBuilder::new()
        .field("EXE", exe.clone())
        .field("PID", "4242")
        .field("UID", format!("{}", nix_uid()))
        .field("SIGNAL", "11")
        .field("CMDLINE", format!("{exe}\0--token=sekrit\0"))
        .field("ENVIRON", "PATH=/usr/bin\0AWS_SECRET_ACCESS_KEY=leak\0")
        .field(
            "PROC_MAPS",
            format!("55f6a1b2b000-55f6a1b2c000 r-xp 0 08:02 1 {exe}\n"),
        )
        .field("PROC_STATUS", "Name:\tfoo\n")
        .field("FILENAME", core.display().to_string())
        .message(format!(
            "Process 4242 ({tag}) dumped core.\n\nStack trace of thread 4242:\n#0  0x00007f00 {tag}_crash (/usr/bin/{tag} + 0x1140)\n#1  0x00007f01 main (/usr/bin/{tag} + 0x1290)\n"
        ))
        .timestamp(1_788_000_000)
        .cursor("s=abc;i=1")
        .build();

    (record, core)
}

fn nix_uid() -> u32 {
    // The tests run unprivileged, so chown is a no-op; the uid still has to round-trip.
    1000
}

fn reporter(
    url: &str,
    crash_dir: &Path,
    state_dir: &Path,
) -> Reporter<RealFs, DpkgBackend<RealFs>> {
    let fs = RealFs;
    let system = system_info(&fs, "6.8.0-test".to_owned());
    let index = DpkgIndex::build_default(&fs);

    let stage1 = Stage1Collector::new(
        fs,
        DpkgBackend::new(
            fs,
            index.clone(),
            "/var/lib/dpkg/info",
            Path::new("/var/lib/dpkg/status"),
        ),
        system,
        "test-machine".to_owned(),
    );
    let stage2 = Stage2Collector::new(
        fs,
        DpkgBackend::new(
            fs,
            index,
            "/var/lib/dpkg/info",
            Path::new("/var/lib/dpkg/status"),
        ),
    );

    let config = ClientConfig {
        endpoint: Endpoint::new(url, TOKEN),
        telemetry_enabled: true,
        state_dir: state_dir.to_path_buf(),
        crash_dir: crash_dir.to_path_buf(),
        kernel_oops: false,
        delete_declined_cores: true,
    };

    let client = Client::new(config.endpoint.clone()).expect("client");
    let spool = Spool::new(config.spool_dir()).expect("spool");
    Reporter::new(stage1, stage2, client, config, spool)
}

macro_rules! setup {
    ($quota:expr) => {{
        let dir = tempfile::tempdir().expect("temp dir");
        let Some(url) = start_server($quota, &dir.path().join("store")).await else {
            eprintln!("skipping: set BLANKRES_TEST_DATABASE_URL to run daemon e2e tests");
            return;
        };
        let crash_dir = dir.path().join("crash");
        let state_dir = dir.path().join("state");
        (dir, reporter(&url, &crash_dir, &state_dir), crash_dir)
    }};
}

fn unique(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{tag}{nanos}")
}

#[tokio::test]
async fn a_wanted_payload_is_written_for_review_and_the_core_survives() {
    let (dir, reporter, _crash_dir) = setup!(5);
    let (record, core) = record(dir.path(), &unique("wanted"));
    let mut state = State::default();

    let outcome = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled");

    let Outcome::AwaitingConsent { path, .. } = outcome else {
        panic!("the first crash of a signature should be wanted, got {outcome:?}");
    };
    assert!(
        core.exists(),
        "the core must survive until the user decides"
    );

    assert!(
        path.parent().is_some_and(|p| p.ends_with("1000")),
        "reports belong in the crashing user's own directory, not a shared one: {}",
        path.display()
    );
    let pending: PendingUpload =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
    assert!(pending.directive.need_payload);
    assert!(pending.directive.upload_token.is_some());
    assert_eq!(pending.report.uid, Some(1000));
}

#[tokio::test]
async fn a_pending_report_is_not_world_readable() {
    let (dir, reporter, _crash_dir) = setup!(5);
    let (record, _core) = record(dir.path(), &unique("perms"));
    let mut state = State::default();

    let Outcome::AwaitingConsent { path, .. } = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled")
    else {
        panic!("expected a payload request");
    };

    // The report carries the crashed process's command line and environment. Other users on the
    // machine have no business reading it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "mode was {:o}", mode & 0o777);
    }
}

#[tokio::test]
async fn a_declined_payload_deletes_the_core_and_writes_nothing() {
    // Quota of zero: the server never wants a payload, which is the steady state once a bug is
    // well known. This is the case that has to be cheap.
    let (dir, reporter, crash_dir) = setup!(0);
    let (record, core) = record(dir.path(), &unique("declined"));
    let mut state = State::default();

    let outcome = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled");

    assert!(
        matches!(outcome, Outcome::ReportedCoreDropped { .. }),
        "{outcome:?}"
    );
    assert!(
        !core.exists(),
        "the core must be reclaimed, not kept like apport does"
    );
    assert!(
        !crash_dir.exists() || std::fs::read_dir(&crash_dir).unwrap().count() == 0,
        "nothing should await consent when no payload was requested"
    );
}

#[tokio::test]
async fn the_stage_two_payload_is_redacted() {
    let (dir, reporter, _crash_dir) = setup!(5);
    let (record, _core) = record(dir.path(), &unique("redact"));
    let mut state = State::default();

    let Outcome::AwaitingConsent { path, .. } = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled")
    else {
        panic!("expected a payload request");
    };

    let raw = std::fs::read_to_string(&path).expect("read");
    assert!(!raw.contains("leak"), "the environment secret reached disk");
    assert!(
        !raw.contains("sekrit"),
        "the command-line secret reached disk"
    );
}

#[tokio::test]
async fn a_declined_signature_is_never_reported_again() {
    let (dir, reporter, _crash_dir) = setup!(5);
    let (record, _core) = record(dir.path(), &unique("neveragain"));
    let mut state = State::default();

    let first = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled");
    let Outcome::AwaitingConsent { signature, .. } = first else {
        panic!("expected a payload request");
    };

    // The user clicks "never for this problem".
    state.decline(&signature);

    let second = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled");
    assert!(matches!(second, Outcome::Suppressed(_)), "{second:?}");
}

#[tokio::test]
async fn a_crash_storm_is_absorbed_by_the_rate_limit() {
    let (dir, reporter, _crash_dir) = setup!(5);
    let (record, _core) = record(dir.path(), &unique("storm"));
    let mut state = State::default();

    let mut suppressed = 0;
    for _ in 0..(RATE_LIMIT + 4) {
        let outcome = reporter
            .handle_coredump(&record, &mut state)
            .await
            .expect("handled");
        if matches!(outcome, Outcome::Suppressed(_)) {
            suppressed += 1;
        }
    }

    assert!(
        suppressed >= 4,
        "the rate limit must absorb a storm, only {suppressed} suppressed"
    );
}

#[tokio::test]
async fn an_unreachable_server_spools_the_event_instead_of_losing_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let crash_dir = dir.path().join("crash");
    let state_dir = dir.path().join("state");
    // Nothing is listening on this port.
    let reporter = reporter("http://127.0.0.1:1", &crash_dir, &state_dir);
    let (record, core) = record(dir.path(), &unique("offline"));
    let mut state = State::default();

    let outcome = reporter
        .handle_coredump(&record, &mut state)
        .await
        .expect("handled");

    assert!(matches!(outcome, Outcome::Spooled { .. }), "{outcome:?}");
    assert!(
        core.exists(),
        "an unsent crash must keep its core for a later attempt"
    );
    let spool = Spool::new(state_dir.join("spool")).expect("spool");
    assert_eq!(spool.len(), 1, "the crash must survive being offline");
}

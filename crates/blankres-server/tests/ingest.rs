//! End-to-end tests for the ingest server.
//!
//! These need a real Postgres, because the payload decision leans on transactional upserts and a
//! single-use UPDATE guard — the two things an in-memory fake would paper over. Set
//! `BLANKRES_TEST_DATABASE_URL` to run them; without it they skip rather than fail, so the rest
//! of the suite stays runnable on a machine with no database.

use blankres_client::{Client, Endpoint};
use blankres_report::event::{CrashEvent, PackageInfo, ReportKind, SystemInfo, SCHEMA_VERSION};
use blankres_report::report::{Attachment, Report, CORE_DUMP_ATTACHMENT};
use blankres_report::signature::{Precision, Signature};
use blankres_server::config::hash_token;
use blankres_server::Config;

const TOKEN: &str = "test-fleet-token";

/// Addresses of servers started by this test binary, so a test can point a differently
/// configured client at the one it just started.
static ADDRESSES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn last_address() -> String {
    ADDRESSES
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("a server was started")
}

fn database_url() -> Option<String> {
    std::env::var("BLANKRES_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
}

/// Start a server on an ephemeral port with its own storage root.
async fn start(quota: i64) -> Option<(Client, tempfile::TempDir)> {
    start_with_tokens(quota, vec![hash_token(TOKEN)]).await
}

/// Start a server with a given set of accepted token hashes. An empty set means the endpoint is
/// open, which is a supported deployment, not a misconfiguration.
async fn start_with_tokens(
    quota: i64,
    token_hashes: Vec<String>,
) -> Option<(Client, tempfile::TempDir)> {
    let database_url = database_url()?;
    let storage = tempfile::tempdir().expect("temp dir");

    let config = Config {
        bind: "127.0.0.1:0".to_owned(),
        database_url,
        storage_root: storage.path().to_path_buf(),
        token_hashes,
        payloads_per_signature: quota,
        max_payload_bytes: 16 * 1024 * 1024,
        upload_token_ttl_secs: 60,
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

    let client = Client::new(Endpoint::new(format!("http://{address}"), TOKEN)).expect("client");
    ADDRESSES.lock().unwrap().push(address.to_string());
    Some((client, storage))
}

/// An event with a signature unique to this test run, so tests can share one database.
fn event(tag: &str, core_size: Option<u64>) -> CrashEvent {
    let hash = blankres_report::signature::Signature::coarse(
        &format!("/usr/bin/{tag}-{}", uuid_like()),
        Some(11),
        Some("1.0-1"),
    )
    .hash;

    CrashEvent {
        schema: SCHEMA_VERSION,
        signature: Signature {
            hash,
            precision: Precision::Precise,
            frames: vec!["parse_config".to_owned(), "main".to_owned()],
        },
        kind: ReportKind::NativeCrash,
        timestamp: 1_788_000_000,
        executable: "/usr/bin/foo".to_owned(),
        signal: Some(11),
        signal_name: Some("SIGSEGV".to_owned()),
        package: PackageInfo {
            name: Some("foo".to_owned()),
            version: Some("1.0-1".to_owned()),
            source: Some("foo".to_owned()),
        },
        system: SystemInfo {
            distro: "Ubuntu".to_owned(),
            distro_version: "24.04".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_version: "6.8.0".to_owned(),
        },
        machine_id: "test-machine".to_owned(),
        crash_count: 1,
        client_version: "0.1.0".to_owned(),
        core_available: core_size.is_some(),
        core_size,
    }
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{nanos}")
}

fn report_for(event: CrashEvent, directive_id: &str, core: &std::path::Path) -> Report {
    Report {
        event,
        directive_id: directive_id.to_owned(),
        command_line: vec!["/usr/bin/foo".to_owned()],
        environment: Default::default(),
        environment_withheld: 3,
        uid: Some(1000),
        stack_trace: Vec::new(),
        modified_files: Vec::new(),
        attachments: vec![Attachment::File {
            name: CORE_DUMP_ATTACHMENT.to_owned(),
            path: core.to_path_buf(),
            size: std::fs::metadata(core).expect("core exists").len(),
            compression: Some("zstd".to_owned()),
        }],
        skipped: Vec::new(),
    }
}

macro_rules! server {
    ($quota:expr) => {
        match start($quota).await {
            Some(pair) => pair,
            None => {
                eprintln!("skipping: set BLANKRES_TEST_DATABASE_URL to run ingest tests");
                return;
            }
        }
    };
}

#[tokio::test]
async fn the_first_crash_of_a_signature_is_asked_for_its_core() {
    let (client, _storage) = server!(1);
    let directives = client
        .send_events(&[event("first", Some(4096))])
        .await
        .expect("sent");

    assert_eq!(directives.len(), 1);
    assert!(directives[0].need_payload);
    assert!(directives[0].upload_token.is_some());
    assert!(directives[0].max_bytes.unwrap() >= 4096);
}

#[tokio::test]
async fn once_the_quota_is_met_further_machines_are_told_not_to_send() {
    let (client, storage) = server!(1);
    let event = event("quota", Some(4096));

    let first = client
        .send_events(std::slice::from_ref(&event))
        .await
        .expect("sent");
    assert!(first[0].need_payload, "first of a signature is wanted");

    // Redeem it, which is what actually increments the stored-payload count.
    let core = storage.path().join("core.zst");
    std::fs::write(&core, vec![7u8; 4096]).expect("write core");
    let report = report_for(event.clone(), &first[0].id, &core);
    client
        .upload_report(&report, &first[0])
        .await
        .expect("uploaded");

    let second = client.send_events(&[event]).await.expect("sent");
    assert!(
        !second[0].need_payload,
        "the quota is what turns a fleet-wide flood of cores into a handful"
    );
    assert!(
        second[0].upload_token.is_none(),
        "no token when none is wanted"
    );
}

#[tokio::test]
async fn a_crash_with_no_core_is_never_asked_for_one() {
    let (client, _storage) = server!(5);
    let directives = client
        .send_events(&[event("nocore", None)])
        .await
        .expect("sent");
    assert!(!directives[0].need_payload);
}

#[tokio::test]
async fn an_upload_token_cannot_be_used_twice() {
    let (client, storage) = server!(5);
    let event = event("replay", Some(1024));
    let directives = client
        .send_events(std::slice::from_ref(&event))
        .await
        .expect("sent");

    let core = storage.path().join("core.zst");
    std::fs::write(&core, vec![3u8; 1024]).expect("write core");
    let report = report_for(event, &directives[0].id, &core);

    client
        .upload_report(&report, &directives[0])
        .await
        .expect("first upload");
    let replay = client.upload_report(&report, &directives[0]).await;
    assert!(replay.is_err(), "a redeemed token must not be reusable");
}

#[tokio::test]
async fn an_unsolicited_payload_is_refused() {
    let (client, storage) = server!(5);
    let event = event("forged", Some(1024));
    let core = storage.path().join("core.zst");
    std::fs::write(&core, vec![1u8; 1024]).expect("write core");

    let forged = blankres_report::event::PayloadDirective {
        id: "made-up".to_owned(),
        need_payload: true,
        upload_token: Some("0".repeat(64)),
        max_bytes: Some(1024 * 1024),
        expires_at: None,
    };

    let result = client
        .upload_report(&report_for(event, "made-up", &core), &forged)
        .await;
    assert!(result.is_err(), "payloads must be requested by the server");
}

#[tokio::test]
async fn the_stored_blob_is_named_by_the_digest_of_what_was_sent() {
    use sha2::{Digest as _, Sha256};

    let (client, storage) = server!(5);
    let event = event("digest", Some(2048));
    let directives = client
        .send_events(std::slice::from_ref(&event))
        .await
        .expect("sent");

    let bytes: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let core = storage.path().join("core.zst");
    std::fs::write(&core, &bytes).expect("write core");
    let expected = hex::encode(Sha256::digest(&bytes));

    let receipt = client
        .upload_report(&report_for(event, &directives[0].id, &core), &directives[0])
        .await
        .expect("uploaded");

    let stored = client.fetch_report(&receipt.id).await.expect("read back");
    assert_eq!(stored["blobs"][CORE_DUMP_ATTACHMENT]["sha256"], expected);
    assert!(
        storage
            .path()
            .join("blobs")
            .join(&expected[..2])
            .join(&expected)
            .exists(),
        "the blob must be on disk at its content address"
    );
}

#[tokio::test]
async fn a_payload_over_the_directives_limit_is_rejected_before_it_is_sent() {
    let (client, storage) = server!(5);
    let event = event("toolarge", Some(1024));
    let directives = client
        .send_events(std::slice::from_ref(&event))
        .await
        .expect("sent");

    // A core far larger than the one the directive was sized for.
    let core = storage.path().join("core.zst");
    std::fs::write(&core, vec![0u8; 8 * 1024 * 1024]).expect("write core");

    let err = client
        .upload_report(&report_for(event, &directives[0].id, &core), &directives[0])
        .await
        .expect_err("must be refused");
    assert!(
        matches!(err, blankres_client::ClientError::TooLarge { .. }),
        "the client should decline locally rather than push bytes the server will drop: {err}"
    );
}

#[tokio::test]
async fn signature_counters_track_events_and_payloads_separately() {
    let (client, storage) = server!(5);
    let event = event("counters", Some(512));

    let first = client
        .send_events(std::slice::from_ref(&event))
        .await
        .expect("sent");
    client
        .send_events(std::slice::from_ref(&event))
        .await
        .expect("sent");

    let core = storage.path().join("core.zst");
    std::fs::write(&core, vec![9u8; 512]).expect("write core");
    client
        .upload_report(&report_for(event.clone(), &first[0].id, &core), &first[0])
        .await
        .expect("uploaded");

    let stats = client
        .fetch_signature(&event.signature.hash)
        .await
        .expect("stats");
    assert_eq!(stats["events"], 2);
    assert_eq!(stats["payloads"], 1, "two crashes, one core stored");
}

#[tokio::test]
async fn a_batch_gets_one_directive_per_event_in_order() {
    let (client, _storage) = server!(5);
    let events = vec![
        event("batch-a", Some(1024)),
        event("batch-b", None),
        event("batch-c", Some(2048)),
    ];

    let directives = client.send_events(&events).await.expect("sent");

    assert_eq!(directives.len(), 3);
    assert!(directives[0].need_payload);
    assert!(
        !directives[1].need_payload,
        "the coreless event in the middle"
    );
    assert!(directives[2].need_payload);
}

#[tokio::test]
async fn an_open_server_accepts_reports_with_no_token_at_all() {
    // Ubuntu's own automatic crash reporting works this way: an open endpoint, with abuse handled
    // by rate limiting rather than a credential.
    let Some((client, _storage)) = start_with_tokens(5, Vec::new()).await else {
        eprintln!("skipping: set BLANKRES_TEST_DATABASE_URL to run ingest tests");
        return;
    };

    let directives = client
        .send_events(&[event("open", Some(4096))])
        .await
        .expect("an open endpoint accepts an unauthenticated report");
    assert_eq!(directives.len(), 1);
}

#[tokio::test]
async fn an_open_server_does_not_care_what_token_is_sent() {
    // The client always sends whatever token it was configured with. On an open server that must
    // not be a reason to reject it, or every already-configured machine would break on the day
    // the operator removes the token.
    let Some((_client, _storage)) = start_with_tokens(5, Vec::new()).await else {
        return;
    };
    let wrong = Client::new(Endpoint::new(
        format!("http://{}", last_address()),
        "a-token-the-server-has-never-heard-of",
    ))
    .expect("client");

    wrong
        .send_events(&[event("opentok", None)])
        .await
        .expect("an open endpoint ignores the token entirely");
}

#[tokio::test]
async fn a_server_with_a_token_still_rejects_the_wrong_one() {
    // The counterpart to open mode: configuring a token must actually enforce it.
    let Some((_client, _storage)) = start_with_tokens(5, vec![hash_token("the-real-one")]).await
    else {
        return;
    };
    let wrong = Client::new(Endpoint::new(
        format!("http://{}", last_address()),
        "not-it",
    ))
    .expect("client");

    let err = wrong
        .send_events(&[event("wrongtok", None)])
        .await
        .expect_err("a configured token must be enforced");
    assert!(format!("{err}").contains("401"), "{err}");
}

//! The stage-1 schema is what every crash on every machine sends, so its size is a budget, and
//! its shape is a contract between the daemon and the server.

use blankres_report::event::{
    CrashEvent, PackageInfo, PayloadDirective, ReportKind, SystemInfo, SCHEMA_VERSION,
};
use blankres_report::signature::{Precision, Signature};

fn sample_event() -> CrashEvent {
    CrashEvent {
        schema: SCHEMA_VERSION,
        signature: Signature {
            hash: "a".repeat(64),
            precision: Precision::Precise,
            frames: vec![
                "parse_config".to_owned(),
                "main".to_owned(),
                "__libc_start_call_main".to_owned(),
                "libc.so.6+0x2a1ca".to_owned(),
                "_start".to_owned(),
            ],
        },
        kind: ReportKind::NativeCrash,
        timestamp: 1_788_000_000,
        executable: "/usr/lib/firefox/firefox".to_owned(),
        signal: Some(11),
        signal_name: Some("SIGSEGV".to_owned()),
        package: PackageInfo {
            name: Some("firefox".to_owned()),
            version: Some("128.0+build1-0ubuntu1".to_owned()),
            source: Some("firefox".to_owned()),
        },
        system: SystemInfo {
            distro: "Ubuntu".to_owned(),
            distro_version: "24.04".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_version: "6.8.0-41-generic".to_owned(),
        },
        machine_id: "b".repeat(64),
        crash_count: 3,
        client_version: "0.1.0".to_owned(),
        core_available: true,
        core_size: Some(412_000_000),
    }
}

#[test]
fn a_stage_one_event_stays_under_its_size_budget() {
    let encoded = serde_json::to_vec(&sample_event()).expect("serializes");
    assert!(
        encoded.len() < 2048,
        "stage-1 event grew to {} bytes; it is sent for every crash on every machine",
        encoded.len()
    );
}

#[test]
fn events_round_trip() {
    let event = sample_event();
    let encoded = serde_json::to_string(&event).expect("serializes");
    let decoded: CrashEvent = serde_json::from_str(&encoded).expect("deserializes");
    assert_eq!(event, decoded);
}

#[test]
fn a_stage_one_event_carries_no_core_dump() {
    // Guards against someone adding a payload-ish field to the cheap stage.
    let encoded = serde_json::to_string(&sample_event()).expect("serializes");
    for forbidden in ["environment", "command_line", "attachments", "stack_trace"] {
        assert!(
            !encoded.contains(forbidden),
            "stage-1 event must not carry `{forbidden}`"
        );
    }
}

#[test]
fn a_declined_directive_hands_out_no_upload_token() {
    let directive = PayloadDirective::not_needed("evt-1");
    assert!(directive.upload_token.is_none());
    assert!(!directive.is_actionable(1_788_000_000));
}

#[test]
fn an_expired_directive_is_not_actionable() {
    let directive = PayloadDirective {
        id: "evt-1".to_owned(),
        need_payload: true,
        upload_token: Some("tok".to_owned()),
        max_bytes: Some(1024),
        expires_at: Some(1_788_000_000),
    };
    assert!(directive.is_actionable(1_787_999_999));
    assert!(!directive.is_actionable(1_788_000_001));
}

#[test]
fn need_payload_without_a_token_is_not_actionable() {
    // A malformed or truncated server response must not send us collecting a core for nothing.
    let directive = PayloadDirective {
        id: "evt-1".to_owned(),
        need_payload: true,
        upload_token: None,
        max_bytes: None,
        expires_at: None,
    };
    assert!(!directive.is_actionable(0));
}

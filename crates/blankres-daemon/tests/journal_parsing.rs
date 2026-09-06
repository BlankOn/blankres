//! Journal decoding. The trap here is that the fields we most want — the NUL-separated command
//! line and environment — are not valid UTF-8, so journald hands them over as byte arrays rather
//! than strings. Handling only the string shape would silently drop exactly the interesting data.

use blankres_daemon::journal::{parse_entry, FixtureSource, JournalSource};

const COREDUMP_LINE: &str = r#"{
  "__CURSOR": "s=abc;i=42",
  "__REALTIME_TIMESTAMP": "1788000000000000",
  "MESSAGE_ID": "fc2e22bc6ee647b6b90729ab34a250b1",
  "MESSAGE": "Process 4242 (foo) of user 1000 dumped core.\n\nStack trace of thread 4242:\n#0  0x00007f8a1b2c3d4e parse_config (/usr/bin/foo + 0x11400)\n",
  "COREDUMP_EXE": "/usr/bin/foo",
  "COREDUMP_PID": "4242",
  "COREDUMP_UID": "1000",
  "COREDUMP_SIGNAL": "11",
  "COREDUMP_FILENAME": "/var/lib/systemd/coredump/core.foo.1000.zst",
  "COREDUMP_CMDLINE": [47,117,115,114,47,98,105,110,47,102,111,111,0,45,45,118],
  "COREDUMP_PROC_MAPS": "55f6a1b2b000-55f6a1b2c000 r-xp 00000000 08:02 262401 /usr/bin/foo\n"
}"#;

#[test]
fn decodes_a_coredump_entry() {
    let entry = parse_entry(&COREDUMP_LINE.replace('\n', "")).expect("parses");
    assert!(entry.is_coredump());
    assert_eq!(entry.cursor, "s=abc;i=42");
    // Microseconds in the journal, seconds in our events.
    assert_eq!(entry.timestamp, 1_788_000_000);
}

#[test]
fn decodes_byte_array_fields_into_text() {
    let entry = parse_entry(&COREDUMP_LINE.replace('\n', "")).expect("parses");
    let cmdline = entry.get("COREDUMP_CMDLINE").expect("cmdline present");
    // The NUL separator must survive: the collectors split on it.
    assert!(cmdline.starts_with("/usr/bin/foo"));
    assert!(cmdline.contains('\0'), "NUL separators must be preserved");
}

#[test]
fn strips_the_coredump_prefix_when_building_a_record() {
    let entry = parse_entry(&COREDUMP_LINE.replace('\n', "")).expect("parses");
    let record = entry.to_coredump_record();

    assert_eq!(record.executable(), Some("/usr/bin/foo"));
    assert_eq!(record.uid(), Some(1000));
    assert_eq!(record.signal(), Some(11));
    assert_eq!(
        record.core_path().as_deref(),
        Some(std::path::Path::new(
            "/var/lib/systemd/coredump/core.foo.1000.zst"
        ))
    );
    assert_eq!(record.cursor, "s=abc;i=42");
}

#[test]
fn a_signal_with_a_name_suffix_still_parses() {
    // systemd writes `11 (SIGSEGV)` in some versions and a bare `11` in others.
    let line = COREDUMP_LINE.replace('\n', "").replace(
        r#""COREDUMP_SIGNAL": "11""#,
        r#""COREDUMP_SIGNAL": "11 (SIGSEGV)""#,
    );
    let record = parse_entry(&line).expect("parses").to_coredump_record();
    assert_eq!(record.signal(), Some(11));
}

#[test]
fn a_malformed_line_is_skipped_rather_than_fatal() {
    assert!(parse_entry("not json at all").is_none());
    assert!(parse_entry("").is_none());
}

#[tokio::test]
async fn a_fixture_source_replays_entries_in_order() {
    let line = COREDUMP_LINE.replace('\n', "");
    let mut source = FixtureSource::from_lines(&[&line, &line]);
    assert!(source.next_entry().await.is_some());
    assert!(source.next_entry().await.is_some());
    assert!(source.next_entry().await.is_none());
}

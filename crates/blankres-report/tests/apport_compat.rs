//! Reading apport's `.crash` format, so reports already on a machine are not stranded.

use blankres_report::apport::{parse, Value};

const FIXTURE: &str = include_str!("fixtures/foo.crash");

#[test]
fn reads_scalar_fields() {
    let fields = parse(FIXTURE).expect("fixture parses");
    assert_eq!(fields["ProblemType"].as_text(), Some("Crash"));
    assert_eq!(fields["ExecutablePath"].as_text(), Some("/usr/bin/foo"));
    assert_eq!(fields["Signal"].as_text(), Some("11"));
    assert_eq!(fields["Package"].as_text(), Some("foo 1.0-1"));
}

#[test]
fn reads_multi_line_continuations() {
    let fields = parse(FIXTURE).expect("fixture parses");
    let status = fields["ProcStatus"].as_text().expect("text field");
    assert!(status.starts_with("Name:\tfoo"));
    assert!(status.contains("Uid:\t1000"));
    assert_eq!(status.lines().count(), 3);
}

#[test]
fn decodes_and_inflates_binary_fields() {
    let fields = parse(FIXTURE).expect("fixture parses");
    let Value::Binary(core) = &fields["CoreDump"] else {
        panic!(
            "CoreDump should decode to binary, got {:?}",
            fields["CoreDump"]
        );
    };
    assert_eq!(&core[..4], b"\x7fELF");
    assert_eq!(core.len(), 964);
}

#[test]
fn rejects_a_continuation_with_no_field() {
    let err = parse(" orphaned continuation\n").unwrap_err();
    assert!(
        err.to_string().contains("continuation before any field"),
        "{err}"
    );
}

#[test]
fn rejects_a_line_that_is_not_a_field() {
    let err = parse("this is not a field\n").unwrap_err();
    assert!(err.to_string().contains("expected"), "{err}");
}

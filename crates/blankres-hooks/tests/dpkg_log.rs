//! Parsing package failures out of dpkg's log.

use blankres_hooks::{newest_timestamp, parse_dpkg_log, terminal_log_tail};

const LOG: &str = "\
2026-09-07 03:14:01 startup archives unpack
2026-09-07 03:14:02 status unpacked foo:amd64 1.0-1
2026-09-07 03:14:03 configure foo:amd64 1.0-1 <none>
2026-09-07 03:14:04 status half-configured foo:amd64 1.0-1
2026-09-07 03:14:05 status installed bar:amd64 2.0-1
2026-09-07 03:15:00 status half-installed baz:amd64 3.0-1
";

#[test]
fn finds_packages_left_in_a_failure_state() {
    let failures = parse_dpkg_log(LOG, None);
    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].package, "foo");
    assert_eq!(failures[0].state, "half-configured");
    assert_eq!(failures[1].package, "baz");
}

#[test]
fn ignores_successful_operations() {
    let failures = parse_dpkg_log(LOG, None);
    assert!(
        !failures.iter().any(|f| f.package == "bar"),
        "an installed package is not a failure"
    );
}

#[test]
fn strips_the_architecture_qualifier() {
    assert!(parse_dpkg_log(LOG, None)
        .iter()
        .all(|f| !f.package.contains(':')));
}

#[test]
fn only_reports_entries_newer_than_the_cursor() {
    // Without this the hook would re-report the same failure after every apt run, forever.
    let failures = parse_dpkg_log(LOG, Some("2026-09-07 03:14:04"));
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].package, "baz");
}

#[test]
fn a_cursor_past_everything_reports_nothing() {
    assert!(parse_dpkg_log(LOG, Some("2026-09-08 00:00:00")).is_empty());
}

#[test]
fn the_cursor_advances_to_the_newest_failure() {
    let failures = parse_dpkg_log(LOG, None);
    assert_eq!(
        newest_timestamp(&failures).as_deref(),
        Some("2026-09-07 03:15:00")
    );
}

#[test]
fn a_package_failing_repeatedly_in_one_run_is_one_report() {
    let repeated = "\
2026-09-07 03:14:04 status half-configured foo:amd64 1.0-1
2026-09-07 03:14:04 status half-configured foo:amd64 1.0-1
";
    assert_eq!(parse_dpkg_log(repeated, None).len(), 1);
}

#[test]
fn the_terminal_log_is_truncated_to_its_tail() {
    let log: String = (0..500).map(|i| format!("line {i}\n")).collect();
    let tail = terminal_log_tail(&log, 20);
    assert_eq!(tail.lines().count(), 20);
    assert!(
        tail.contains("line 499"),
        "the end of the log is where the error is"
    );
}

#[test]
fn a_package_failure_event_never_asks_for_a_core_dump() {
    use blankres_report::event::{ReportKind, SystemInfo};
    let failures = parse_dpkg_log(LOG, None);
    let event = failures[0].to_event(
        Some("1.0-1".to_owned()),
        SystemInfo::default(),
        "machine".to_owned(),
        1,
        1_788_000_000,
    );
    assert_eq!(event.kind, ReportKind::PackageFailure);
    assert!(
        !event.core_available,
        "there is no core dump for a failed postinst"
    );
}

#[test]
fn different_packages_failing_get_different_signatures() {
    use blankres_report::event::SystemInfo;
    let failures = parse_dpkg_log(LOG, None);
    let first = failures[0].to_event(None, SystemInfo::default(), "m".to_owned(), 1, 0);
    let second = failures[1].to_event(None, SystemInfo::default(), "m".to_owned(), 1, 0);
    assert_ne!(first.signature.hash, second.signature.hash);
}

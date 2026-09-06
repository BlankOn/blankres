//! Kernel oops handling. One oops is a burst of lines; filing one report per line would drown the
//! crash database in noise, so coalescing is the property under test.

use blankres_daemon::oops::{parse_call_trace, starts_oops, OopsBuilder};
use blankres_report::event::{ReportKind, SystemInfo};
use blankres_report::signature::Precision;

const OOPS: &[&str] = &[
    "BUG: kernel NULL pointer dereference, address: 0000000000000018",
    "#PF: supervisor read access in kernel mode",
    "Oops: 0000 [#1] PREEMPT SMP NOPTI",
    "CPU: 3 PID: 1234 Comm: kworker/3:1 Not tainted 6.8.0-41-generic",
    "Call Trace:",
    " <TASK>",
    " ? __die+0x23/0x70",
    " ? page_fault_oops+0x171/0x4e0",
    " nvme_queue_rq+0x1c9/0x4c0 [nvme]",
    " blk_mq_dispatch_rq_list+0x2f0/0x8a0",
];

fn system() -> SystemInfo {
    SystemInfo {
        distro: "Ubuntu".to_owned(),
        distro_version: "24.04".to_owned(),
        architecture: "x86_64".to_owned(),
        kernel_version: "6.8.0-41-generic".to_owned(),
    }
}

fn build() -> OopsBuilder {
    let mut builder = OopsBuilder::new(1_788_000_000, OOPS[0]);
    for line in &OOPS[1..] {
        builder.push(*line);
    }
    builder
}

#[test]
fn recognizes_the_lines_that_begin_an_oops() {
    assert!(starts_oops(
        "BUG: kernel NULL pointer dereference, address: 0x18"
    ));
    assert!(starts_oops("Oops: 0000 [#1] PREEMPT SMP NOPTI"));
    assert!(starts_oops("kernel BUG at fs/ext4/inode.c:2341!"));
    assert!(!starts_oops("usb 1-3: new high-speed USB device number 5"));
}

#[test]
fn a_burst_of_lines_becomes_one_report() {
    let builder = build();
    let event = builder.to_event(system(), "machine".to_owned(), 1);
    assert_eq!(event.kind, ReportKind::KernelOops);
    assert_eq!(
        builder.lines.len(),
        OOPS.len(),
        "all lines coalesced into one"
    );
}

#[test]
fn the_signature_comes_from_the_call_trace() {
    let event = build().to_event(system(), "machine".to_owned(), 1);
    assert_eq!(event.signature.precision, Precision::Precise);
    // `__die` and `page_fault_oops` are the fault machinery, present in every oops; the driver
    // frame is what distinguishes this bug.
    assert!(
        event.signature.frames.iter().any(|f| f == "nvme_queue_rq"),
        "frames: {:?}",
        event.signature.frames
    );
}

#[test]
fn two_different_oopses_do_not_share_a_signature() {
    let first = build().to_event(system(), "m".to_owned(), 1);

    let mut other = OopsBuilder::new(1_788_000_100, OOPS[0]);
    other.push("Call Trace:");
    other.push(" ext4_do_update_inode+0x1c9/0x4c0");
    let second = other.to_event(system(), "m".to_owned(), 1);

    assert_ne!(first.signature.hash, second.signature.hash);
}

#[test]
fn an_oops_never_claims_to_have_a_core_dump() {
    let event = build().to_event(system(), "machine".to_owned(), 1);
    assert!(
        !event.core_available,
        "there is no core dump for a kernel oops"
    );
    assert_eq!(event.core_size, None);
}

#[test]
fn a_later_line_outside_the_window_is_not_the_same_oops() {
    let builder = build();
    assert!(builder.accepts(1_788_000_005));
    assert!(!builder.accepts(1_788_000_100));
}

#[test]
fn offsets_are_stripped_from_kernel_frames() {
    // Offsets shift with every kernel build; keeping them would fork the signature per kernel.
    let lines: Vec<String> = OOPS.iter().map(|s| (*s).to_owned()).collect();
    let frames = parse_call_trace(&lines);
    assert!(frames.iter().all(|f| {
        f.function
            .as_deref()
            .is_some_and(|name| !name.contains("0x"))
    }));
}

#[test]
fn an_oops_with_no_call_trace_still_reports_coarsely() {
    let builder = OopsBuilder::new(1_788_000_000, "kernel panic - not syncing: Fatal exception");
    let event = builder.to_event(system(), "machine".to_owned(), 1);
    assert_eq!(event.signature.precision, Precision::Coarse);
}

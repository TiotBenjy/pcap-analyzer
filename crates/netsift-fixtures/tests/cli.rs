//! The `netsift-fixtures gen` binary.

mod common;

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_netsift-fixtures"))
        .args(args)
        .output()
        .expect("binary runs")
}

#[test]
fn gen_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().to_str().unwrap();
    let res = run(&["gen", "--out", out, "--scenario", "dns", "--format", "pcap"]);
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    let path = dir.path().join("capture.pcap");
    let packets = common::read_file(&path);
    assert_eq!(packets.len(), 8, "four DNS exchanges");
    assert!(String::from_utf8_lossy(&res.stdout).contains("capture.pcap"));
}

#[test]
fn gen_split_by_size_with_dumpcap_names() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().to_str().unwrap();
    let res = run(&[
        "gen",
        "--out",
        out,
        "--repeat",
        "5",
        "--split",
        "size=20k",
        "--naming",
        "dumpcap",
        "--gzip",
        "--start-number",
        "123456",
    ]);
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(names.len() > 2, "{names:?}");
    assert!(
        names
            .iter()
            .all(|n| n.starts_with("capture_123") && n.ends_with(".pcapng.gz"))
    );
    let expected = netsift_fixtures::scenarios::generate(
        netsift_fixtures::scenarios::Kind::Demo,
        5,
        netsift_fixtures::scenario::DEFAULT_SEED,
    );
    let total: usize = names
        .iter()
        .map(|n| common::read_file(&dir.path().join(n)).len())
        .sum();
    assert_eq!(total, expected.len());
}

#[test]
fn gen_rejects_bad_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().to_str().unwrap();
    assert!(
        !run(&["gen", "--out", out, "--scenario", "nope"])
            .status
            .success()
    );
    assert!(
        !run(&["gen", "--out", out, "--split", "lines=4"])
            .status
            .success()
    );
    assert!(
        !run(&["gen", "--out", out, "--split", "duration=-1"])
            .status
            .success()
    );
}

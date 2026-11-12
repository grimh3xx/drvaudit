//! The demo snapshot must keep producing the findings shown in docs/demo.svg.
use std::process::Command;

#[test]
fn linux_snapshot_findings() {
    let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/linux-snapshot");
    let out = Command::new(env!("CARGO_BIN_EXE_drvaudit"))
        .args(["--json", "--min-severity", "info", "--root", fx])
        .env("DRVAUDIT_CACHE", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    for id in ["DRV-010", "DRV-007", "DRV-006", "DRV-016"] {
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
    let hidden: Vec<&serde_json::Value> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"] == "DRV-010")
        .collect();
    assert_eq!(
        hidden.len(),
        1,
        "built-in kobject without initstate must not be flagged"
    );
}

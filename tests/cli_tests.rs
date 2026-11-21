use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn check_catches_left_join_demotion_and_not_in_and_soft_delete() {
    let dir = tempdir().unwrap();
    let sql_path = dir.path().join("buggy.sql");
    std::fs::write(
        &sql_path,
        r#"
        WITH active_students AS (
          SELECT s.id AS sid, p.user_id
          FROM populi.people s
          LEFT JOIN canvas.pseudonyms p ON p.sis_user_id = s.id
          WHERE p.workflow_state = 'active'
            AND s.id NOT IN (SELECT student_id FROM populi.exits)
        )
        SELECT * FROM active_students a
        LEFT JOIN canvas.submissions sub ON sub.user_id = a.user_id;
        "#,
    )
    .unwrap();

    let output = Command::cargo_bin("auditkeel")
        .unwrap()
        .args(["check", sql_path.to_str().unwrap(), "--format", "agent"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "fail");
    assert_eq!(json["cte_count"], 1);
    assert_eq!(json["join_count"], 2);

    let codes: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"LEFT_JOIN_DEMOTION"));
    assert!(codes.contains(&"NOT_IN_NULL_TRAP"));
    assert!(codes.contains(&"SOFT_DELETE_UNFILTERED"));
    assert!(codes.contains(&"SELECT_STAR"));
}

#[test]
fn check_passes_clean_query_with_exit_zero() {
    let output = Command::cargo_bin("auditkeel")
        .unwrap()
        .args([
            "check",
            "--sql",
            "WITH base AS (SELECT id, score FROM scores WHERE score >= 0) SELECT id, score FROM base",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "pass");
    assert_eq!(json["cte_count"], 1);
    assert_eq!(json["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn skill_prints_and_installs_cleanly() {
    Command::cargo_bin("auditkeel")
        .unwrap()
        .arg("skill")
        .assert()
        .success()
        .stdout(predicate::str::contains("name: auditkeel"));

    let dir = tempdir().unwrap();
    Command::cargo_bin("auditkeel")
        .unwrap()
        .args(["skill", "--install", dir.path().to_str().unwrap()])
        .assert()
        .success();

    let installed = dir.path().join("auditkeel").join("SKILL.md");
    assert!(installed.exists());
}

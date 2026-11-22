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
fn check_catches_function_demotion_3way_union_lateral_and_per_table_soft_delete() {
    // 1. LEFT JOIN demotion via LOWER(...) + multi-table per-alias soft-delete + qualified wildcard
    let sql1 = r#"
        WITH joined AS (
          SELECT s.id, p.user_id, c.id AS course_id
          FROM populi.people s
          LEFT JOIN canvas.pseudonyms p
            ON p.sis_user_id = s.id AND p.workflow_state <> 'deleted'
          LEFT JOIN canvas.courses c
            ON c.account_id = s.id
          WHERE LOWER(p.workflow_state) = 'active'
        )
        SELECT j.* FROM joined j;
    "#;
    let out1 = Command::cargo_bin("auditkeel")
        .unwrap()
        .args(["check", "--sql", sql1, "--format", "agent"])
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(1));
    let j1: Value = serde_json::from_slice(&out1.stdout).unwrap();
    let codes1: Vec<&str> = j1["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes1.contains(&"LEFT_JOIN_DEMOTION"));
    assert!(codes1.contains(&"SOFT_DELETE_UNFILTERED"));
    assert!(codes1.contains(&"SELECT_STAR"));

    // 2. 3-way UNION ALL with LEFT JOIN demotion in 3rd branch + LATERAL unfiltered Canvas table
    let sql2 = r#"
        SELECT id FROM t1
        UNION ALL
        SELECT id FROM t2
        UNION ALL
        SELECT a.id FROM t3 a
        LEFT JOIN t4 b ON b.id = a.id
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS n FROM canvas.submissions sub WHERE sub.user_id = a.id
        ) lat ON TRUE
        WHERE b.score BETWEEN 10 AND 20
    "#;
    let out2 = Command::cargo_bin("auditkeel")
        .unwrap()
        .args(["check", "--sql", sql2, "--format", "agent"])
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(1));
    let j2: Value = serde_json::from_slice(&out2.stdout).unwrap();
    let codes2: Vec<&str> = j2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes2.contains(&"LEFT_JOIN_DEMOTION"));
    assert!(codes2.contains(&"SOFT_DELETE_UNFILTERED"));
}

#[test]
fn help_hides_database_url_env_value() {
    let out = Command::cargo_bin("auditkeel")
        .unwrap()
        .env("DATABASE_URL", "postgres://secret_user:SUPER_SECRET_PASS@db.internal/prod")
        .args(["run", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8_lossy(&out);
    assert!(!help.contains("SUPER_SECRET_PASS"));
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

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::parse::ParsedQuery;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub location: String,
    pub message: String,
    pub fix_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CteStep {
    pub name: String,
    pub row_count: i64,
    pub prev_row_count: Option<i64>,
    pub ratio_vs_prev: Option<f64>,
    pub referenced_ctes: Vec<String>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct JoinProbe {
    pub scope: String,
    pub join_type: String,
    pub left_relation: String,
    pub right_relation: String,
    pub left_key: String,
    pub right_key: String,
    pub left_rows: Option<i64>,
    pub right_rows: Option<i64>,
    pub right_distinct_keys: Option<i64>,
    pub right_dup_key_pct: Option<f64>,
    pub right_max_dupes: Option<i64>,
    pub matched_left_pct: Option<f64>,
    pub unmatched_left_rows: Option<i64>,
    pub fanout_factor: Option<f64>,
    pub sample_unmatched_keys: Vec<String>,
    pub probe_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpotCheckTrace {
    pub key_value: String,
    pub cte_counts: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrainAudit {
    pub key_columns: Vec<String>,
    pub total_rows: i64,
    pub distinct_keys: i64,
    pub duplicate_rows: i64,
    pub null_key_rows: i64,
    pub is_unique: bool,
    pub sample_duplicate_keys: Vec<String>,
    pub spot_checks: Vec<SpotCheckTrace>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub tool: String,
    pub version: String,
    pub mode: String,
    pub source: String,
    pub audited_at: DateTime<Utc>,
    pub query_sha256: String,
    pub status: String,
    pub cte_count: usize,
    pub join_count: usize,
    pub final_row_count: Option<i64>,
    pub waterfall: Vec<CteStep>,
    pub joins: Vec<JoinProbe>,
    pub grain: Option<GrainAudit>,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn from_static(source: &str, raw_sql: &str, parsed: &ParsedQuery) -> Self {
        let hash = sha256_hex(raw_sql);
        let status = compute_status(&parsed.static_findings);
        Self {
            tool: "auditkeel".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            mode: "static_check".to_string(),
            source: source.to_string(),
            audited_at: Utc::now(),
            query_sha256: hash,
            status,
            cte_count: parsed.ctes.len(),
            join_count: parsed.joins.len(),
            final_row_count: None,
            waterfall: Vec::new(),
            joins: Vec::new(),
            grain: None,
            findings: parsed.static_findings.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ColumnTypeDiff {
    pub column: String,
    pub old_type: String,
    pub new_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumericColDiff {
    pub column: String,
    pub old_sum: Option<f64>,
    pub new_sum: Option<f64>,
    pub sum_delta: Option<f64>,
    pub old_nulls: i64,
    pub new_nulls: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyOverlapDiff {
    pub key_columns: Vec<String>,
    pub in_both: i64,
    pub only_in_old: i64,
    pub only_in_new: i64,
    pub sample_only_in_old: Vec<String>,
    pub sample_only_in_new: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub tool: String,
    pub version: String,
    pub audited_at: DateTime<Utc>,
    pub old_source: String,
    pub new_source: String,
    pub old_sha256: String,
    pub new_sha256: String,
    pub old_row_count: i64,
    pub new_row_count: i64,
    pub row_delta: i64,
    pub added_columns: Vec<String>,
    pub removed_columns: Vec<String>,
    pub type_diffs: Vec<ColumnTypeDiff>,
    pub key_overlap: Option<KeyOverlapDiff>,
    pub numeric_diffs: Vec<NumericColDiff>,
    pub has_drift: bool,
    pub status: String,
}

pub fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let bytes = hasher.finalize();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn compute_status(findings: &[Finding]) -> String {
    if findings.iter().any(|f| f.severity == Severity::Error) {
        "fail".to_string()
    } else if findings.iter().any(|f| f.severity == Severity::Warn) {
        "warn".to_string()
    } else {
        "pass".to_string()
    }
}

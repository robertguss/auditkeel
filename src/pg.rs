//! Read-only PostgreSQL execution engine for CTE waterfalls, composite join probes, grain & diffs.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::{Duration, Instant};

use chrono::Utc;
use native_tls::TlsConnector;
use postgres::config::{Host, SslMode};
use postgres::{Client, Config, NoTls, Transaction};
use postgres_native_tls::MakeTlsConnector;

use crate::model::{
    AuditReport, ColumnTypeDiff, CteStep, DiffReport, Finding, GrainAudit, JoinProbe,
    KeyOverlapDiff, NumericColDiff, Severity, SpotCheckTrace, compute_status, sha256_hex,
};
use crate::parse::{self, ParsedJoin, ParsedQuery};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedSsl {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

fn scrub_dsn_error(mut msg: String) -> String {
    // Redact any `://user:password@` credential fragment (using rfind for `@` in passwords)
    // and any libpq keyword `password=...` fragment if echoed in an error.
    if let Some(scheme_end) = msg.find("://") {
        let rest = &msg[scheme_end + 3..];
        let auth_end = rest.find(['/', '?', ' ']).unwrap_or(rest.len());
        let auth = &rest[..auth_end];
        if let Some(at_pos) = auth.rfind('@')
            && auth[..at_pos].contains(':')
        {
            msg = format!("{}://***@{}", &msg[..scheme_end], &rest[at_pos + 1..]);
        }
    }
    let lower = msg.to_lowercase();
    if let Some(pw_pos) = lower.find("password=") {
        let val_start = pw_pos + "password=".len();
        let tail = &msg[val_start..];
        let val_len = if let Some(after_q) = tail.strip_prefix('\'') {
            after_q.find('\'').map(|i| i + 2).unwrap_or(tail.len())
        } else {
            tail.find(char::is_whitespace).unwrap_or(tail.len())
        };
        msg = format!("{}***{}", &msg[..val_start], &msg[val_start + val_len..]);
    }
    msg
}

fn normalize_dsn_sslmode(dsn: &str) -> (String, RequestedSsl) {
    let lower = dsn.to_lowercase();
    if lower.contains("sslmode=verify-full") {
        let rewritten = dsn
            .replace("sslmode=verify-full", "sslmode=require")
            .replace("SSLMODE=VERIFY-FULL", "sslmode=require");
        (rewritten, RequestedSsl::VerifyFull)
    } else if lower.contains("sslmode=verify-ca") {
        let rewritten = dsn
            .replace("sslmode=verify-ca", "sslmode=require")
            .replace("SSLMODE=VERIFY-CA", "sslmode=require");
        (rewritten, RequestedSsl::VerifyCa)
    } else if lower.contains("sslmode=disable") {
        (dsn.to_string(), RequestedSsl::Disable)
    } else if lower.contains("sslmode=require") {
        (dsn.to_string(), RequestedSsl::Require)
    } else {
        (dsn.to_string(), RequestedSsl::Prefer)
    }
}

fn is_loopback_config(cfg: &Config) -> bool {
    let hosts = cfg.get_hosts();
    if hosts.is_empty() {
        return true;
    }
    hosts.iter().all(|h| match h {
        #[cfg(unix)]
        Host::Unix(_) => true,
        Host::Tcp(addr) => {
            let low = addr.to_lowercase();
            low == "localhost" || low == "127.0.0.1" || low == "::1"
        }
    })
}

pub fn connect_postgres(dsn: &str) -> Result<Client, String> {
    let (norm_dsn, req_ssl) = normalize_dsn_sslmode(dsn);
    let mut cfg = Config::from_str(&norm_dsn)
        .map_err(|e| scrub_dsn_error(format!("invalid PostgreSQL DSN: {e}")))?;
    if cfg.get_connect_timeout().is_none() {
        cfg.connect_timeout(Duration::from_secs(10));
    }

    let loopback = is_loopback_config(&cfg);
    match req_ssl {
        RequestedSsl::Disable => cfg
            .connect(NoTls)
            .map_err(|e| scrub_dsn_error(format!("PostgreSQL connection failed: {e}"))),
        RequestedSsl::Prefer if loopback => {
            cfg.ssl_mode(SslMode::Disable);
            cfg.connect(NoTls)
                .map_err(|e| scrub_dsn_error(format!("PostgreSQL local connection failed: {e}")))
        }
        RequestedSsl::Prefer | RequestedSsl::Require | RequestedSsl::VerifyFull => {
            // Remote host or required TLS: enforce TLS with full certificate & hostname verification.
            // Never silently downgrade a remote connection to plaintext NoTls!
            cfg.ssl_mode(SslMode::Require);
            let connector = TlsConnector::builder()
                .build()
                .map_err(|e| format!("TLS initialization failed: {e}"))?;
            let tls = MakeTlsConnector::new(connector);
            cfg.connect(tls)
                .map_err(|e| scrub_dsn_error(format!("PostgreSQL TLS connection failed: {e}")))
        }
        RequestedSsl::VerifyCa => {
            cfg.ssl_mode(SslMode::Require);
            let connector = TlsConnector::builder()
                .danger_accept_invalid_hostnames(true)
                .build()
                .map_err(|e| format!("TLS initialization failed: {e}"))?;
            let tls = MakeTlsConnector::new(connector);
            cfg.connect(tls).map_err(|e| {
                scrub_dsn_error(format!("PostgreSQL TLS (verify-ca) connection failed: {e}"))
            })
        }
    }
}

fn configure_readonly_session(tx: &mut Transaction<'_>, timeout_secs: u64) -> Result<(), String> {
    let eff_timeout = timeout_secs.max(1);
    tx.execute("SET LOCAL TimeZone = 'UTC'", &[])
        .map_err(|e| format!("failed setting UTC timezone: {e}"))?;
    tx.execute("SET LOCAL lock_timeout = '5s'", &[])
        .map_err(|e| format!("failed setting lock_timeout: {e}"))?;
    tx.execute(
        &format!("SET LOCAL statement_timeout = '{eff_timeout}s'"),
        &[],
    )
    .map_err(|e| format!("failed setting statement_timeout: {e}"))?;
    Ok(())
}

fn format_pg_err(err: &postgres::Error) -> String {
    if let Some(db) = err.as_db_error() {
        let mut msg = format!("{}: {}", db.severity(), db.message());
        if let Some(detail) = db.detail() {
            msg.push_str(&format!(" ({detail})"));
        }
        if let Some(hint) = db.hint() {
            msg.push_str(&format!(" [hint: {hint}]"));
        }
        msg
    } else {
        err.to_string()
    }
}

fn quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn build_cte_prefix(parsed: &ParsedQuery, up_to_exclusive: usize) -> String {
    if up_to_exclusive == 0 || parsed.ctes.is_empty() {
        return String::new();
    }
    let defs: Vec<String> = parsed.ctes[..up_to_exclusive]
        .iter()
        .map(|c| {
            let cols = if c.alias_columns.is_empty() {
                String::new()
            } else {
                let qcols: Vec<String> =
                    c.alias_columns.iter().map(|col| quote_ident(col)).collect();
                format!("({})", qcols.join(", "))
            };
            format!("{}{cols} AS (\n{}\n)", quote_ident(&c.name), c.query_sql)
        })
        .collect();
    let rec = if parsed.with_recursive {
        "RECURSIVE "
    } else {
        ""
    };
    format!("WITH {rec}{}\n", defs.join(",\n"))
}

#[allow(clippy::too_many_arguments)]
pub fn run_live_audit(
    dsn: &str,
    source: &str,
    raw_sql: &str,
    parsed: &ParsedQuery,
    keys: &[String],
    spot_checks: usize,
    max_fanout: f64,
    min_rows: Option<i64>,
    timeout_secs: u64,
) -> Result<AuditReport, String> {
    let mut client = connect_postgres(dsn)?;
    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| format!("failed to start read-only transaction: {e}"))?;
    configure_readonly_session(&mut tx, timeout_secs)?;

    let mut findings = parsed.static_findings.clone();
    let mut waterfall: Vec<CteStep> = Vec::new();
    let mut counts_by_cte: std::collections::HashMap<String, i64> =
        std::collections::HashMap::new();

    // 1. CTE Row-Count Waterfall (execute each CTE + FINAL safely read-only)
    for idx in 0..parsed.ctes.len() {
        let cte = &parsed.ctes[idx];
        let prefix = build_cte_prefix(parsed, idx + 1);
        let probe_sql = format!(
            "{prefix}SELECT count(*)::bigint FROM {}",
            quote_ident(&cte.name)
        );
        let t0 = Instant::now();
        let row = tx
            .query_one(&probe_sql, &[])
            .map_err(|e| format!("failed counting CTE `{}`: {}", cte.name, format_pg_err(&e)))?;
        let count: i64 = row.get(0);

        let parent_count: Option<i64> = cte
            .primary_from_cte
            .as_deref()
            .and_then(|p| counts_by_cte.get(p).copied())
            .or_else(|| {
                cte.referenced_ctes
                    .iter()
                    .filter_map(|r| counts_by_cte.get(r).copied())
                    .max()
            });
        let ratio = parent_count.and_then(|p| {
            if p > 0 {
                Some(count as f64 / p as f64)
            } else {
                None
            }
        });

        if count == 0 && parent_count.unwrap_or(0) > 0 {
            findings.push(Finding {
                code: "ZERO_ROW_COLLAPSE".to_string(),
                severity: Severity::Error,
                location: cte.name.clone(),
                message: format!(
                    "CTE `{}` collapsed to 0 rows (down from {} in parent CTE).",
                    cte.name,
                    parent_count.unwrap_or(0)
                ),
                fix_hint: format!(
                    "Inspect WHERE filters and JOIN keys inside CTE `{}` for overly strict or mismatched predicates.",
                    cte.name
                ),
            });
        } else if let Some(r) = ratio
            && r > max_fanout
        {
            findings.push(Finding {
                code: "CTE_ROW_EXPANSION".to_string(),
                severity: Severity::Warn,
                location: cte.name.clone(),
                message: format!(
                    "CTE `{}` expanded rows by {:.2}x ({} -> {}). Verify this is intentional and not a join fan-out.",
                    cte.name,
                    r,
                    parent_count.unwrap_or(0),
                    count
                ),
                fix_hint: format!(
                    "Check right-hand JOIN tables in `{}` for duplicate join keys (use `DISTINCT ON` or pre-aggregate).",
                    cte.name
                ),
            });
        }

        waterfall.push(CteStep {
            name: cte.name.clone(),
            row_count: count,
            prev_row_count: parent_count,
            ratio_vs_prev: ratio.map(|v| (v * 1000.0).round() / 1000.0),
            referenced_ctes: cte.referenced_ctes.clone(),
            elapsed_ms: t0.elapsed().as_millis(),
        });
        counts_by_cte.insert(cte.name.clone(), count);
    }

    // FINAL row count — compare against actual DAG parent CTEs referenced by FINAL!
    let final_sql = format!(
        "SELECT count(*)::bigint FROM (\n{}\n) AS _auditkeel_final",
        parsed.full_query_sql
    );
    let t_fin = Instant::now();
    let final_count: i64 = tx
        .query_one(&final_sql, &[])
        .map_err(|e| format!("failed counting final query: {}", format_pg_err(&e)))?
        .get(0);

    let final_parent_count: Option<i64> = parsed
        .final_primary_from_cte
        .as_deref()
        .and_then(|p| counts_by_cte.get(p).copied())
        .or_else(|| {
            parsed
                .final_referenced_ctes
                .iter()
                .filter_map(|r| counts_by_cte.get(r).copied())
                .max()
        });
    let final_ratio = final_parent_count.and_then(|p| {
        if p > 0 {
            Some(final_count as f64 / p as f64)
        } else {
            None
        }
    });

    if final_count == 0 && final_parent_count.unwrap_or(0) > 0 {
        findings.push(Finding {
            code: "ZERO_ROW_COLLAPSE".to_string(),
            severity: Severity::Error,
            location: "FINAL".to_string(),
            message: format!(
                "FINAL query collapsed to 0 rows (down from {} in parent CTE).",
                final_parent_count.unwrap_or(0)
            ),
            fix_hint: "Check final WHERE predicates and INNER/LEFT JOIN conditions.".to_string(),
        });
    } else if let Some(r) = final_ratio
        && r > max_fanout
    {
        findings.push(Finding {
            code: "CTE_ROW_EXPANSION".to_string(),
            severity: Severity::Warn,
            location: "FINAL".to_string(),
            message: format!(
                "FINAL query expanded rows by {:.2}x ({} -> {}).",
                r,
                final_parent_count.unwrap_or(0),
                final_count
            ),
            fix_hint: "Verify join cardinality on the final SELECT or pass `--key` to verify entity grain.".to_string(),
        });
    }
    if let Some(min_r) = min_rows
        && final_count < min_r
    {
        findings.push(Finding {
            code: "MIN_ROWS_VIOLATION".to_string(),
            severity: Severity::Error,
            location: "FINAL".to_string(),
            message: format!(
                "FINAL query returned {final_count} row(s), below configured min_rows = {min_r}."
            ),
            fix_hint: "Verify upstream table sync completeness and WHERE filters.".to_string(),
        });
    }

    waterfall.push(CteStep {
        name: "FINAL".to_string(),
        row_count: final_count,
        prev_row_count: final_parent_count,
        ratio_vs_prev: final_ratio.map(|v| (v * 1000.0).round() / 1000.0),
        referenced_ctes: parsed.final_referenced_ctes.clone(),
        elapsed_ms: t_fin.elapsed().as_millis(),
    });

    // 2. Live Join Cardinality, Composite-Key Fan-Out & Match Coverage Probes
    let mut join_probes: Vec<JoinProbe> = Vec::new();
    for j in &parsed.joins {
        let probe = probe_join(&mut tx, parsed, j, timeout_secs);
        let lk_label = j.left_key_cols.join(", ");
        let rk_label = j.right_key_cols.join(", ");
        if let Some(fanout) = probe.fanout_factor
            && fanout > max_fanout
        {
            findings.push(Finding {
                code: "JOIN_FANOUT".to_string(),
                severity: Severity::Error,
                location: format!("{} ({} -> {})", j.scope, j.left_relation, j.right_relation),
                message: format!(
                    "{} `{}` ON `({}) = ({})` fans out rows by {:.2}x (lookup side has {:.1}% duplicate keys, max {} rows/key).",
                    j.join_type,
                    j.right_relation,
                    lk_label,
                    rk_label,
                    fanout,
                    probe.right_dup_key_pct.unwrap_or(0.0),
                    probe.right_max_dupes.unwrap_or(1),
                ),
                fix_hint: format!(
                    "Deduplicate `{}` to 1 row per ({}) using `SELECT DISTINCT ON ({}) ...` or pre-aggregate before joining.",
                    j.right_relation, rk_label, rk_label
                ),
            });
        }
        if let Some(cov) = probe.matched_left_pct
            && cov < 80.0
            && probe.left_rows.unwrap_or(0) > 0
        {
            findings.push(Finding {
                code: "LOW_JOIN_COVERAGE".to_string(),
                severity: Severity::Warn,
                location: format!("{} ({} -> {})", j.scope, j.left_relation, j.right_relation),
                message: format!(
                    "Only {:.1}% of left rows in `{}` matched `{}` on `({}) = ({})` ({} unmatched rows).",
                    cov,
                    j.left_relation,
                    j.right_relation,
                    lk_label,
                    rk_label,
                    probe.unmatched_left_rows.unwrap_or(0),
                ),
                fix_hint: "Inspect sample_unmatched_keys for type/trim/leading-zero mismatches or missing bridge rows.".to_string(),
            });
        }
        join_probes.push(probe);
    }

    // 3. Entity Grain Uniqueness & Concrete Spot-Check Traces (when --key or --rules provided)
    let grain = if !keys.is_empty() {
        let g = audit_grain(&mut tx, parsed, keys, spot_checks)?;
        if g.duplicate_rows > 0 {
            findings.push(Finding {
                code: "GRAIN_DUPLICATES".to_string(),
                severity: Severity::Error,
                location: "FINAL".to_string(),
                message: format!(
                    "Final result is NOT unique on grain key ({}): {} total rows vs {} distinct keys ({} duplicate rows).",
                    keys.join(", "),
                    g.total_rows,
                    g.distinct_keys,
                    g.duplicate_rows
                ),
                fix_hint: format!(
                    "Trace duplicate sample keys ({}) back through the CTE waterfall to eliminate fan-out.",
                    g.sample_duplicate_keys.join(", ")
                ),
            });
        }
        if g.null_key_rows > 0 {
            findings.push(Finding {
                code: "NULL_GRAIN_KEY".to_string(),
                severity: Severity::Error,
                location: "FINAL".to_string(),
                message: format!(
                    "{} final rows have NULL in grain key ({}).",
                    g.null_key_rows,
                    keys.join(", ")
                ),
                fix_hint: "Filter or coalesce NULL grain keys before final projection.".to_string(),
            });
        }
        Some(g)
    } else {
        None
    };

    let _ = tx.rollback();
    let status = compute_status(&findings);
    Ok(AuditReport {
        tool: "auditkeel".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: "live_postgres".to_string(),
        source: source.to_string(),
        audited_at: Utc::now(),
        query_sha256: sha256_hex(raw_sql),
        status,
        cte_count: parsed.ctes.len(),
        join_count: parsed.joins.len(),
        final_row_count: Some(final_count),
        waterfall,
        joins: join_probes,
        grain,
        findings,
    })
}

fn composite_key_expr(alias: &str, keys: &[String]) -> String {
    // Collision-free JSONB array serialization (immune to embedded `|` or literal `<NULL>`)
    let parts: Vec<String> = keys
        .iter()
        .map(|k| format!("({alias}.{})::text", quote_ident(k)))
        .collect();
    format!("jsonb_build_array({})::text", parts.join(", "))
}

fn non_null_all_expr(alias: &str, keys: &[String]) -> String {
    keys.iter()
        .map(|k| format!("{alias}.{} IS NOT NULL", quote_ident(k)))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn any_key_null_expr(alias: &str, keys: &[String]) -> String {
    keys.iter()
        .map(|k| format!("{alias}.{} IS NULL", quote_ident(k)))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn probe_key_expr(alias: &str, keys: &[String]) -> String {
    if keys.len() == 1 {
        format!("({alias}.{})::text", quote_ident(&keys[0]))
    } else {
        composite_key_expr(alias, keys)
    }
}

fn probe_join(
    tx: &mut Transaction<'_>,
    parsed: &ParsedQuery,
    j: &ParsedJoin,
    timeout_secs: u64,
) -> JoinProbe {
    let (lrel, rrel, lcols, rcols) = if j.is_right {
        (
            &j.right_relation,
            &j.left_relation,
            &j.right_key_cols,
            &j.left_key_cols,
        )
    } else {
        (
            &j.left_relation,
            &j.right_relation,
            &j.left_key_cols,
            &j.right_key_cols,
        )
    };

    let mut base = JoinProbe {
        scope: j.scope.clone(),
        join_type: j.join_type.clone(),
        left_relation: j.left_relation.clone(),
        right_relation: j.right_relation.clone(),
        left_key: j.left_key_cols.join(", "),
        right_key: j.right_key_cols.join(", "),
        left_rows: None,
        right_rows: None,
        right_distinct_keys: None,
        right_dup_key_pct: None,
        right_max_dupes: None,
        matched_left_pct: None,
        unmatched_left_rows: None,
        fanout_factor: None,
        sample_unmatched_keys: Vec::new(),
        probe_error: None,
    };

    if lrel.starts_with('(') || rrel.starts_with('(') || lcols.is_empty() || rcols.is_empty() {
        base.probe_error = Some("skipped derived subquery join probe".to_string());
        return base;
    }

    // Determine CTE prefix visible to j.scope
    let top_scope = j.scope.split('.').next().unwrap_or(&j.scope);
    let cte_idx = if top_scope == "FINAL" {
        parsed.ctes.len()
    } else {
        parsed
            .ctes
            .iter()
            .position(|c| c.name == top_scope)
            .unwrap_or(0)
    };
    let prefix = build_cte_prefix(parsed, cte_idx);

    let l_kexpr = probe_key_expr("_l", lcols);
    let l_not_null = non_null_all_expr("_l", lcols);
    let r_kexpr = probe_key_expr("_r", rcols);
    let r_not_null = non_null_all_expr("_r", rcols);

    let Ok(mut sp) = tx.savepoint("auditkeel_join_probe") else {
        base.probe_error = Some("failed to create savepoint".to_string());
        return base;
    };

    let probe_timeout = timeout_secs.clamp(1, 30);
    let _ = sp.execute(
        &format!("SET LOCAL statement_timeout = '{probe_timeout}s'"),
        &[],
    );

    // Single-pass hash-aggregated probe: scans each side ONCE and computes exact join
    // cardinality via SUM(l.cnt * r.cnt) without materializing M:N row explosions.
    let with_clause = if prefix.is_empty() {
        "WITH ".to_string()
    } else {
        format!("{},\n", prefix.trim_end())
    };
    let stats_sql = format!(
        "{with_clause}_ak_l AS (
          SELECT {l_kexpr} AS _k, ({l_not_null}) AS _nn, count(*)::bigint AS cnt
          FROM {lrel} _l
          GROUP BY 1, 2
        ),
        _ak_r AS (
          SELECT {r_kexpr} AS _k, ({r_not_null}) AS _nn, count(*)::bigint AS cnt
          FROM {rrel} _r
          GROUP BY 1, 2
        ),
        _ak_j AS (
          SELECT
            coalesce(sum(l.cnt::numeric * r.cnt::numeric), 0)::bigint AS joined_rows,
            coalesce(sum(l.cnt), 0)::bigint AS matched_l
          FROM _ak_l l
          JOIN _ak_r r ON l._nn AND r._nn AND l._k = r._k
        )
        SELECT
          coalesce((SELECT sum(cnt)::bigint FROM _ak_l), 0) AS l_rows,
          coalesce((SELECT sum(cnt)::bigint FROM _ak_r), 0) AS r_rows,
          coalesce((SELECT count(*)::bigint FROM _ak_r WHERE _nn), 0) AS r_dist,
          coalesce((SELECT max(cnt)::bigint FROM _ak_r WHERE _nn), 0) AS r_max,
          coalesce((SELECT count(*)::bigint FROM _ak_r WHERE _nn AND cnt > 1), 0) AS r_dup_keys,
          (SELECT joined_rows FROM _ak_j) AS joined_rows,
          (SELECT matched_l FROM _ak_j) AS matched_l,
          coalesce(
            (SELECT array_agg(k) FROM (
              SELECT coalesce(l._k, '<NULL>') AS k
              FROM _ak_l l
              LEFT JOIN _ak_r r ON r._nn AND r._k = l._k
              WHERE NOT l._nn OR r._k IS NULL
              ORDER BY 1
              LIMIT 3
            ) _u),
            ARRAY[]::text[]
          ) AS sample_unmatched"
    );

    match sp.query_one(&stats_sql, &[]) {
        Ok(row) => {
            let l_rows: i64 = row.get(0);
            let r_rows: i64 = row.get(1);
            let r_dist: i64 = row.get(2);
            let r_max: i64 = row.get(3);
            let r_dup_keys: i64 = row.get(4);
            let joined_rows: i64 = row.get(5);
            let matched_l: i64 = row.get(6);
            let sample_unmatched: Vec<String> = row.get(7);

            base.left_rows = Some(l_rows);
            base.right_rows = Some(r_rows);
            base.right_distinct_keys = Some(r_dist);
            base.right_max_dupes = Some(r_max);
            base.right_dup_key_pct = Some(if r_dist > 0 {
                ((r_dup_keys as f64 / r_dist as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            });
            base.unmatched_left_rows = Some((l_rows - matched_l).max(0));
            base.matched_left_pct = Some(if l_rows > 0 {
                ((matched_l as f64 / l_rows as f64) * 1000.0).round() / 10.0
            } else {
                100.0
            });
            base.fanout_factor = Some(if matched_l > 0 {
                ((joined_rows as f64 / matched_l as f64) * 1000.0).round() / 1000.0
            } else {
                1.0
            });
            if l_rows > matched_l {
                base.sample_unmatched_keys = sample_unmatched;
            }
            let _ = sp.commit();
        }
        Err(e) => {
            base.probe_error = Some(format!("join probe skipped: {}", format_pg_err(&e)));
            let _ = sp.rollback();
        }
    }
    base
}

fn audit_grain(
    tx: &mut Transaction<'_>,
    parsed: &ParsedQuery,
    keys: &[String],
    spot_checks: usize,
) -> Result<GrainAudit, String> {
    let kexpr = composite_key_expr("_f", keys);
    let nexpr = any_key_null_expr("_f", keys);
    let grain_sql = format!(
        "SELECT
           count(*)::bigint,
           count(DISTINCT ({kexpr}))::bigint,
           count(*) FILTER (WHERE {nexpr})::bigint
         FROM (\n{}\n) AS _f",
        parsed.full_query_sql
    );
    let row = tx.query_one(&grain_sql, &[]).map_err(|e| {
        format!(
            "grain check failed on key ({}): {}",
            keys.join(", "),
            format_pg_err(&e)
        )
    })?;
    let total: i64 = row.get(0);
    let distinct: i64 = row.get(1);
    let nulls: i64 = row.get(2);
    let dupes = (total - distinct).max(0);

    let mut sample_dupes = Vec::new();
    if dupes > 0 {
        let dup_sql = format!(
            "SELECT ({kexpr}) AS k
             FROM (\n{}\n) AS _f
             GROUP BY 1 HAVING count(*) > 1
             ORDER BY count(*) DESC, 1
             LIMIT 3",
            parsed.full_query_sql
        );
        if let Ok(rows) = tx.query(&dup_sql, &[]) {
            sample_dupes = rows.into_iter().map(|r| r.get(0)).collect();
        }
    }

    let mut traces = Vec::new();
    if spot_checks > 0 && total > 0 {
        let pick_sql = format!(
            "SELECT DISTINCT ({kexpr}) AS k FROM (\n{}\n) AS _f ORDER BY 1 LIMIT {}",
            parsed.full_query_sql, spot_checks
        );
        if let Ok(picked) = tx.query(&pick_sql, &[]) {
            for r in picked {
                let kval: String = r.get(0);
                let mut cte_counts = Vec::new();
                for idx in 0..parsed.ctes.len() {
                    let cte = &parsed.ctes[idx];
                    let prefix = build_cte_prefix(parsed, idx + 1);
                    let cte_kexpr = composite_key_expr("_c", keys);
                    let probe = format!(
                        "{prefix}SELECT count(*)::bigint FROM {} AS _c WHERE ({cte_kexpr}) = $1",
                        quote_ident(&cte.name)
                    );
                    if let Ok(mut sp) = tx.savepoint("spot_check_cte") {
                        if let Ok(cr) = sp.query_one(&probe, &[&kval]) {
                            cte_counts.push((cte.name.clone(), cr.get::<_, i64>(0)));
                            let _ = sp.commit();
                        } else {
                            let _ = sp.rollback();
                        }
                    }
                }
                let fin_probe = format!(
                    "SELECT count(*)::bigint FROM (\n{}\n) AS _f WHERE ({kexpr}) = $1",
                    parsed.full_query_sql
                );
                if let Ok(fr) = tx.query_one(&fin_probe, &[&kval]) {
                    cte_counts.push(("FINAL".to_string(), fr.get::<_, i64>(0)));
                }
                traces.push(SpotCheckTrace {
                    key_value: kval,
                    cte_counts,
                });
            }
        }
    }

    Ok(GrainAudit {
        key_columns: keys.to_vec(),
        total_rows: total,
        distinct_keys: distinct,
        duplicate_rows: dupes,
        null_key_rows: nulls,
        is_unique: dupes == 0 && nulls == 0,
        sample_duplicate_keys: sample_dupes,
        spot_checks: traces,
    })
}

pub fn run_live_diff(
    dsn: &str,
    old_source: &str,
    old_sql_raw: &str,
    new_source: &str,
    new_sql_raw: &str,
    keys: &[String],
    timeout_secs: u64,
) -> Result<DiffReport, String> {
    let old_parsed = parse::analyze_sql(old_sql_raw)?;
    let new_parsed = parse::analyze_sql(new_sql_raw)?;
    let old_sql = &old_parsed.full_query_sql;
    let new_sql = &new_parsed.full_query_sql;

    let mut client = connect_postgres(dsn)?;
    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| format!("failed to start read-only diff transaction: {e}"))?;
    configure_readonly_session(&mut tx, timeout_secs)?;

    let old_cnt: i64 = tx
        .query_one(
            &format!("SELECT count(*)::bigint FROM (\n{old_sql}\n) _a"),
            &[],
        )
        .map_err(|e| format!("old query failed: {e}"))?
        .get(0);
    let new_cnt: i64 = tx
        .query_one(
            &format!("SELECT count(*)::bigint FROM (\n{new_sql}\n) _b"),
            &[],
        )
        .map_err(|e| format!("new query failed: {e}"))?
        .get(0);

    let old_stmt = tx
        .prepare(&format!("SELECT * FROM (\n{old_sql}\n) _a LIMIT 0"))
        .map_err(|e| format!("failed inspecting old columns: {e}"))?;
    let new_stmt = tx
        .prepare(&format!("SELECT * FROM (\n{new_sql}\n) _b LIMIT 0"))
        .map_err(|e| format!("failed inspecting new columns: {e}"))?;

    let old_cols: Vec<(String, String)> = old_stmt
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_().name().to_string()))
        .collect();
    let new_cols: Vec<(String, String)> = new_stmt
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_().name().to_string()))
        .collect();

    let old_set: HashSet<&str> = old_cols.iter().map(|(n, _)| n.as_str()).collect();
    let new_set: HashSet<&str> = new_cols.iter().map(|(n, _)| n.as_str()).collect();
    let added_columns: Vec<String> = new_cols
        .iter()
        .filter(|(n, _)| !old_set.contains(n.as_str()))
        .map(|(n, _)| n.clone())
        .collect();
    let removed_columns: Vec<String> = old_cols
        .iter()
        .filter(|(n, _)| !new_set.contains(n.as_str()))
        .map(|(n, _)| n.clone())
        .collect();

    // Key overlap diff (collision-free JSONB keys)
    let key_overlap = if !keys.is_empty() {
        let ka = composite_key_expr("_a", keys);
        let kb = composite_key_expr("_b", keys);
        let ov_sql = format!(
            "WITH a AS (SELECT DISTINCT ({ka}) AS k FROM (\n{old_sql}\n) _a),
                  b AS (SELECT DISTINCT ({kb}) AS k FROM (\n{new_sql}\n) _b)
             SELECT
               (SELECT count(*)::bigint FROM a JOIN b USING (k)),
               (SELECT count(*)::bigint FROM a LEFT JOIN b USING (k) WHERE b.k IS NULL),
               (SELECT count(*)::bigint FROM b LEFT JOIN a USING (k) WHERE a.k IS NULL)"
        );
        let r = tx
            .query_one(&ov_sql, &[])
            .map_err(|e| format!("key overlap diff failed: {e}"))?;
        let in_both: i64 = r.get(0);
        let only_old: i64 = r.get(1);
        let only_new: i64 = r.get(2);

        let sample_old: Vec<String> = if only_old > 0 {
            tx.query(
                &format!(
                    "WITH a AS (SELECT DISTINCT ({ka}) AS k FROM (\n{old_sql}\n) _a),
                          b AS (SELECT DISTINCT ({kb}) AS k FROM (\n{new_sql}\n) _b)
                     SELECT a.k FROM a LEFT JOIN b USING (k) WHERE b.k IS NULL ORDER BY 1 LIMIT 3"
                ),
                &[],
            )
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.get(0))
            .collect()
        } else {
            Vec::new()
        };
        let sample_new: Vec<String> = if only_new > 0 {
            tx.query(
                &format!(
                    "WITH a AS (SELECT DISTINCT ({ka}) AS k FROM (\n{old_sql}\n) _a),
                          b AS (SELECT DISTINCT ({kb}) AS k FROM (\n{new_sql}\n) _b)
                     SELECT b.k FROM b LEFT JOIN a USING (k) WHERE a.k IS NULL ORDER BY 1 LIMIT 3"
                ),
                &[],
            )
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.get(0))
            .collect()
        } else {
            Vec::new()
        };

        Some(KeyOverlapDiff {
            key_columns: keys.to_vec(),
            in_both,
            only_in_old: only_old,
            only_in_new: only_new,
            sample_only_in_old: sample_old,
            sample_only_in_new: sample_new,
        })
    } else {
        None
    };

    // Shared column type drift detection + batched numeric column aggregate drift
    let new_type_map: std::collections::HashMap<&str, &str> = new_cols
        .iter()
        .map(|(n, ty)| (n.as_str(), ty.as_str()))
        .collect();
    let type_diffs: Vec<ColumnTypeDiff> = old_cols
        .iter()
        .filter_map(|(c, old_ty)| {
            new_type_map.get(c.as_str()).and_then(|new_ty| {
                if old_ty.as_str() != *new_ty {
                    Some(ColumnTypeDiff {
                        column: c.clone(),
                        old_type: old_ty.clone(),
                        new_type: (*new_ty).to_string(),
                    })
                } else {
                    None
                }
            })
        })
        .collect();

    // Only cast/sum columns that are numeric in BOTH old and new queries so a type change
    // on one column can never poison the batched aggregate query for other numeric columns.
    let numeric_types = ["int2", "int4", "int8", "float4", "float8", "numeric"];
    let common_num_cols: Vec<&str> = old_cols
        .iter()
        .filter(|(c, old_ty)| {
            numeric_types.contains(&old_ty.as_str())
                && new_type_map
                    .get(c.as_str())
                    .is_some_and(|new_ty| numeric_types.contains(new_ty))
        })
        .map(|(c, _)| c.as_str())
        .collect();

    let mut numeric_diffs = Vec::new();
    let mut num_drifted = false;

    if !common_num_cols.is_empty() {
        let select_exprs: Vec<String> = common_num_cols
            .iter()
            .map(|c| {
                let q = quote_ident(c);
                format!("sum(({q})::double precision), count(*) FILTER (WHERE {q} IS NULL)::bigint")
            })
            .collect();
        let proj = select_exprs.join(", ");
        let ro = tx
            .query_one(&format!("SELECT {proj} FROM (\n{old_sql}\n) _a"), &[])
            .map_err(|e| format!("failed aggregating numeric columns on old query: {e}"))?;
        let rn = tx
            .query_one(&format!("SELECT {proj} FROM (\n{new_sql}\n) _b"), &[])
            .map_err(|e| format!("failed aggregating numeric columns on new query: {e}"))?;

        for (idx, col_name) in common_num_cols.iter().enumerate() {
            let os: Option<f64> = ro.get(idx * 2);
            let on: i64 = ro.get(idx * 2 + 1);
            let ns: Option<f64> = rn.get(idx * 2);
            let nn: i64 = rn.get(idx * 2 + 1);

            let raw_delta = match (os, ns) {
                (Some(a), Some(b)) => Some(b - a),
                _ => None,
            };
            let nan_or_presence_changed =
                os.map(f64::is_nan) != ns.map(f64::is_nan) || os.is_some() != ns.is_some();
            if nan_or_presence_changed
                || raw_delta.is_some_and(|v| !v.is_finite() || v.abs() > 1e-6)
                || on != nn
            {
                num_drifted = true;
            }
            numeric_diffs.push(NumericColDiff {
                column: (*col_name).to_string(),
                old_sum: os.map(|v| {
                    if v.is_finite() {
                        (v * 1000.0).round() / 1000.0
                    } else {
                        v
                    }
                }),
                new_sum: ns.map(|v| {
                    if v.is_finite() {
                        (v * 1000.0).round() / 1000.0
                    } else {
                        v
                    }
                }),
                sum_delta: raw_delta.map(|v| {
                    if v.is_finite() {
                        (v * 1_000_000.0).round() / 1_000_000.0
                    } else {
                        v
                    }
                }),
                old_nulls: on,
                new_nulls: nn,
            });
        }
    }

    let _ = tx.rollback();
    let row_delta = new_cnt - old_cnt;
    let key_drifted = key_overlap
        .as_ref()
        .is_some_and(|k| k.only_in_old > 0 || k.only_in_new > 0);
    let has_drift = row_delta != 0
        || !added_columns.is_empty()
        || !removed_columns.is_empty()
        || !type_diffs.is_empty()
        || key_drifted
        || num_drifted;

    Ok(DiffReport {
        tool: "auditkeel".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        audited_at: Utc::now(),
        old_source: old_source.to_string(),
        new_source: new_source.to_string(),
        old_sha256: sha256_hex(old_sql),
        new_sha256: sha256_hex(new_sql),
        old_row_count: old_cnt,
        new_row_count: new_cnt,
        row_delta,
        added_columns,
        removed_columns,
        type_diffs,
        key_overlap,
        numeric_diffs,
        has_drift,
        status: if has_drift {
            "drift_detected".to_string()
        } else {
            "identical".to_string()
        },
    })
}

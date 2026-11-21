//! Read-only PostgreSQL execution engine for CTE waterfalls, join probes, grain & diffs.

use std::collections::HashSet;
use std::time::Instant;

use chrono::Utc;
use native_tls::TlsConnector;
use postgres::{Client, NoTls, Transaction};
use postgres_native_tls::MakeTlsConnector;

use crate::model::{
    AuditReport, CteStep, DiffReport, Finding, GrainAudit, JoinProbe, KeyOverlapDiff,
    NumericColDiff, Severity, SpotCheckTrace, compute_status, sha256_hex,
};
use crate::parse::{ParsedJoin, ParsedQuery};

pub fn connect_postgres(dsn: &str) -> Result<Client, String> {
    let lower = dsn.to_lowercase();
    let disable_tls = lower.contains("sslmode=disable")
        || lower.contains("127.0.0.1")
        || lower.contains("localhost");
    if disable_tls {
        Client::connect(dsn, NoTls).map_err(|e| format!("PostgreSQL connection failed: {e}"))
    } else {
        let connector = TlsConnector::builder()
            .build()
            .map_err(|e| format!("TLS initialization failed: {e}"))?;
        let tls = MakeTlsConnector::new(connector);
        match Client::connect(dsn, tls) {
            Ok(c) => Ok(c),
            Err(tls_err) => Client::connect(dsn, NoTls).map_err(|plain_err| {
                format!("PostgreSQL connection failed (TLS: {tls_err}; NoTls: {plain_err})")
            }),
        }
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
        .map(|c| format!("{} AS ({})", quote_ident(&c.name), c.query_sql))
        .collect();
    format!("WITH {} ", defs.join(", "))
}

pub fn run_live_audit(
    dsn: &str,
    source: &str,
    raw_sql: &str,
    parsed: &ParsedQuery,
    keys: &[String],
    spot_checks: usize,
    max_fanout: f64,
) -> Result<AuditReport, String> {
    let mut client = connect_postgres(dsn)?;
    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| format!("failed to start read-only transaction: {e}"))?;

    let mut findings = parsed.static_findings.clone();
    let mut waterfall: Vec<CteStep> = Vec::new();
    let mut counts_by_cte: std::collections::HashMap<String, i64> =
        std::collections::HashMap::new();
    let mut prev_count: Option<i64> = None;

    // 1. CTE Row-Count Waterfall (execute each CTE + FINAL safely read-only)
    for idx in 0..parsed.ctes.len() {
        let cte = &parsed.ctes[idx];
        let prefix = build_cte_prefix(parsed, idx + 1);
        let probe_sql = format!("{prefix}SELECT count(*)::bigint FROM {}", quote_ident(&cte.name));
        let t0 = Instant::now();
        let row = tx
            .query_one(&probe_sql, &[])
            .map_err(|e| format!("failed counting CTE `{}`: {e}", cte.name))?;
        let count: i64 = row.get(0);

        // Compare against the actual parent CTE in the DAG (max referenced parent row count),
        // NOT an unrelated sibling lookup CTE!
        let parent_count: Option<i64> = cte
            .referenced_ctes
            .iter()
            .filter_map(|r| counts_by_cte.get(r).copied())
            .max();
        let ratio = parent_count.and_then(|p| if p > 0 { Some(count as f64 / p as f64) } else { None });

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
        prev_count = Some(count);
    }

    // FINAL row count
    let final_sql = format!(
        "SELECT count(*)::bigint FROM ({}) AS _auditkeel_final",
        parsed.full_query_sql
    );
    let t_fin = Instant::now();
    let final_count: i64 = tx
        .query_one(&final_sql, &[])
        .map_err(|e| format!("failed counting final query: {e}"))?
        .get(0);
    let final_ratio = prev_count.and_then(|p| if p > 0 { Some(final_count as f64 / p as f64) } else { None });
    if final_count == 0 && prev_count.unwrap_or(0) > 0 {
        findings.push(Finding {
            code: "ZERO_ROW_COLLAPSE".to_string(),
            severity: Severity::Error,
            location: "FINAL".to_string(),
            message: format!(
                "FINAL query collapsed to 0 rows (down from {} in prior CTE).",
                prev_count.unwrap_or(0)
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
                prev_count.unwrap_or(0),
                final_count
            ),
            fix_hint: "Verify join cardinality on the final SELECT or pass `--key` to verify entity grain.".to_string(),
        });
    }
    waterfall.push(CteStep {
        name: "FINAL".to_string(),
        row_count: final_count,
        prev_row_count: prev_count,
        ratio_vs_prev: final_ratio.map(|v| (v * 1000.0).round() / 1000.0),
        referenced_ctes: parsed
            .ctes
            .last()
            .map(|c| vec![c.name.clone()])
            .unwrap_or_default(),
        elapsed_ms: t_fin.elapsed().as_millis(),
    });

    // 2. Live Join Cardinality, Fan-Out & Match Coverage Probes
    let mut join_probes: Vec<JoinProbe> = Vec::new();
    for j in &parsed.joins {
        let probe = probe_join(&mut tx, parsed, j);
        if let Some(fanout) = probe.fanout_factor
            && fanout > max_fanout
        {
            findings.push(Finding {
                code: "JOIN_FANOUT".to_string(),
                severity: Severity::Error,
                location: format!("{} ({} -> {})", j.scope, j.left_relation, j.right_relation),
                message: format!(
                    "{} `{}` ON `{}.{} = {}.{}` fans out rows by {:.2}x (right table has {:.1}% duplicate keys, max {} rows/key).",
                    j.join_type,
                    j.right_relation,
                    j.left_alias,
                    j.left_key_col,
                    j.right_alias,
                    j.right_key_col,
                    fanout,
                    probe.right_dup_key_pct.unwrap_or(0.0),
                    probe.right_max_dupes.unwrap_or(1),
                ),
                fix_hint: format!(
                    "Deduplicate `{}` to 1 row per `{}` using `SELECT DISTINCT ON ({}) ...` or aggregate before joining.",
                    j.right_relation, j.right_key_col, j.right_key_col
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
                    "Only {:.1}% of left rows in `{}` matched `{}` on `{} = {}` ({} unmatched rows).",
                    cov,
                    j.left_relation,
                    j.right_relation,
                    j.left_key_col,
                    j.right_key_col,
                    probe.unmatched_left_rows.unwrap_or(0),
                ),
                fix_hint: "Inspect sample_unmatched_keys for type/trim/leading-zero mismatches or missing bridge rows.".to_string(),
            });
        }
        join_probes.push(probe);
    }

    // 3. Entity Grain Uniqueness & Concrete Spot-Check Traces (when --key provided)
    let grain = if !keys.is_empty() {
        let g = audit_grain(&mut tx, parsed, keys, spot_checks)?;
        if !g.is_unique {
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
                severity: Severity::Warn,
                location: "FINAL".to_string(),
                message: format!(
                    "{} final rows have NULL in grain key ({}).",
                    g.null_key_rows,
                    keys.join(", ")
                ),
                fix_hint: "Filter or coalesce NULL keys before final aggregation.".to_string(),
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

fn probe_join(tx: &mut Transaction<'_>, parsed: &ParsedQuery, j: &ParsedJoin) -> JoinProbe {
    let mut base = JoinProbe {
        scope: j.scope.clone(),
        join_type: j.join_type.clone(),
        left_relation: j.left_relation.clone(),
        right_relation: j.right_relation.clone(),
        left_key: j.left_key_col.clone(),
        right_key: j.right_key_col.clone(),
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

    if j.left_relation.starts_with('(') || j.right_relation.starts_with('(') {
        base.probe_error = Some("skipped derived subquery join probe".to_string());
        return base;
    }

    // Determine CTE prefix visible to j.scope
    let cte_idx = if j.scope == "FINAL" {
        parsed.ctes.len()
    } else {
        parsed
            .ctes
            .iter()
            .position(|c| c.name == j.scope)
            .unwrap_or(0)
    };
    let prefix = build_cte_prefix(parsed, cte_idx);
    let lk = quote_ident(&j.left_key_col);
    let rk = quote_ident(&j.right_key_col);

    // Use a SAVEPOINT so a probe error never aborts the outer read-only transaction!
    let Ok(mut sp) = tx.savepoint("auditkeel_join_probe") else {
        base.probe_error = Some("failed to create savepoint".to_string());
        return base;
    };

    let stats_sql = format!(
        "{prefix}
        SELECT
          (SELECT count(*)::bigint FROM {lrel}) AS l_rows,
          (SELECT count(*)::bigint FROM {rrel}) AS r_rows,
          (SELECT count(DISTINCT ({rk})::text)::bigint FROM {rrel} WHERE {rk} IS NOT NULL) AS r_dist,
          coalesce((SELECT max(cnt)::bigint FROM (SELECT count(*) AS cnt FROM {rrel} WHERE {rk} IS NOT NULL GROUP BY ({rk})::text) _d), 0) AS r_max,
          coalesce((SELECT count(*)::bigint FROM (SELECT 1 FROM {rrel} WHERE {rk} IS NOT NULL GROUP BY ({rk})::text HAVING count(*) > 1) _d2), 0) AS r_dup_keys,
          (SELECT count(*)::bigint FROM {lrel} _l JOIN {rrel} _r ON (_l.{lk})::text = (_r.{rk})::text) AS joined_rows,
          (SELECT count(*)::bigint FROM {lrel} _l WHERE EXISTS (SELECT 1 FROM {rrel} _r WHERE (_l.{lk})::text = (_r.{rk})::text)) AS matched_l
        ",
        lrel = j.left_relation,
        rrel = j.right_relation,
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
                let sample_sql = format!(
                    "{prefix}
                    SELECT DISTINCT coalesce((_l.{lk})::text, '<NULL>')
                    FROM {lrel} _l
                    WHERE NOT EXISTS (SELECT 1 FROM {rrel} _r WHERE (_l.{lk})::text = (_r.{rk})::text)
                    LIMIT 3",
                    lrel = j.left_relation,
                    rrel = j.right_relation,
                );
                if let Ok(srows) = sp.query(&sample_sql, &[]) {
                    base.sample_unmatched_keys = srows.into_iter().map(|r| r.get(0)).collect();
                }
            }
            let _ = sp.commit();
        }
        Err(e) => {
            base.probe_error = Some(format!("join probe skipped: {e}"));
            let _ = sp.rollback();
        }
    }
    base
}

fn composite_key_expr(alias: &str, keys: &[String]) -> String {
    let parts: Vec<String> = keys
        .iter()
        .map(|k| format!("coalesce(({alias}.{})::text, '<NULL>')", quote_ident(k)))
        .collect();
    parts.join(" || '|' || ")
}

fn any_key_null_expr(alias: &str, keys: &[String]) -> String {
    keys.iter()
        .map(|k| format!("{alias}.{} IS NULL", quote_ident(k)))
        .collect::<Vec<_>>()
        .join(" OR ")
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
         FROM ({}) AS _f",
        parsed.full_query_sql
    );
    let row = tx
        .query_one(&grain_sql, &[])
        .map_err(|e| format!("grain check failed on key ({}): {e}", keys.join(", ")))?;
    let total: i64 = row.get(0);
    let distinct: i64 = row.get(1);
    let nulls: i64 = row.get(2);
    let dupes = (total - distinct).max(0);

    let mut sample_dupes = Vec::new();
    if dupes > 0 {
        let dup_sql = format!(
            "SELECT ({kexpr}) AS k
             FROM ({}) AS _f
             GROUP BY 1 HAVING count(*) > 1
             ORDER BY count(*) DESC, 1
             LIMIT 3",
            parsed.full_query_sql
        );
        if let Ok(rows) = tx.query(&dup_sql, &[]) {
            sample_dupes = rows.into_iter().map(|r| r.get(0)).collect();
        }
    }

    // Spot-check concrete entity keys across every CTE that contains those key column(s)
    let mut traces = Vec::new();
    if spot_checks > 0 && total > 0 {
        let pick_sql = format!(
            "SELECT DISTINCT ({kexpr}) AS k FROM ({}) AS _f ORDER BY 1 LIMIT {}",
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
                    "SELECT count(*)::bigint FROM ({}) AS _f WHERE ({kexpr}) = $1",
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
        is_unique: dupes == 0,
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
) -> Result<DiffReport, String> {
    let old_sql = old_sql_raw.trim().trim_end_matches(';').trim();
    let new_sql = new_sql_raw.trim().trim_end_matches(';').trim();
    let mut client = connect_postgres(dsn)?;
    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| format!("failed to start read-only diff transaction: {e}"))?;

    let old_cnt: i64 = tx
        .query_one(&format!("SELECT count(*)::bigint FROM ({old_sql}) _a"), &[])
        .map_err(|e| format!("old query failed: {e}"))?
        .get(0);
    let new_cnt: i64 = tx
        .query_one(&format!("SELECT count(*)::bigint FROM ({new_sql}) _b"), &[])
        .map_err(|e| format!("new query failed: {e}"))?
        .get(0);

    let old_stmt = tx
        .prepare(&format!("SELECT * FROM ({old_sql}) _a LIMIT 0"))
        .map_err(|e| format!("failed inspecting old columns: {e}"))?;
    let new_stmt = tx
        .prepare(&format!("SELECT * FROM ({new_sql}) _b LIMIT 0"))
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

    // Key overlap diff
    let key_overlap = if !keys.is_empty() {
        let ka = composite_key_expr("_a", keys);
        let kb = composite_key_expr("_b", keys);
        let ov_sql = format!(
            "WITH a AS (SELECT DISTINCT ({ka}) AS k FROM ({old_sql}) _a),
                  b AS (SELECT DISTINCT ({kb}) AS k FROM ({new_sql}) _b)
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
                    "WITH a AS (SELECT DISTINCT ({ka}) AS k FROM ({old_sql}) _a),
                          b AS (SELECT DISTINCT ({kb}) AS k FROM ({new_sql}) _b)
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
                    "WITH a AS (SELECT DISTINCT ({ka}) AS k FROM ({old_sql}) _a),
                          b AS (SELECT DISTINCT ({kb}) AS k FROM ({new_sql}) _b)
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

    // Numeric column aggregate drift
    let numeric_types = ["int2", "int4", "int8", "float4", "float8", "numeric"];
    let mut numeric_diffs = Vec::new();
    for (col_name, ty_name) in &old_cols {
        if !new_set.contains(col_name.as_str()) || !numeric_types.contains(&ty_name.as_str()) {
            continue;
        }
        let qcol = quote_ident(col_name);
        let agg_old = tx.query_one(
            &format!(
                "SELECT sum(({qcol})::double precision), count(*) FILTER (WHERE {qcol} IS NULL)::bigint FROM ({old_sql}) _a"
            ),
            &[],
        );
        let agg_new = tx.query_one(
            &format!(
                "SELECT sum(({qcol})::double precision), count(*) FILTER (WHERE {qcol} IS NULL)::bigint FROM ({new_sql}) _b"
            ),
            &[],
        );
        if let (Ok(ro), Ok(rn)) = (agg_old, agg_new) {
            let os: Option<f64> = ro.get(0);
            let on: i64 = ro.get(1);
            let ns: Option<f64> = rn.get(0);
            let nn: i64 = rn.get(1);
            let delta = match (os, ns) {
                (Some(a), Some(b)) => Some(((b - a) * 1000.0).round() / 1000.0),
                _ => None,
            };
            numeric_diffs.push(NumericColDiff {
                column: col_name.clone(),
                old_sum: os.map(|v| (v * 1000.0).round() / 1000.0),
                new_sum: ns.map(|v| (v * 1000.0).round() / 1000.0),
                sum_delta: delta,
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
    let num_drifted = numeric_diffs
        .iter()
        .any(|d| d.sum_delta.is_some_and(|v| v.abs() > 1e-6) || d.old_nulls != d.new_nulls);
    let has_drift = row_delta != 0
        || !added_columns.is_empty()
        || !removed_columns.is_empty()
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

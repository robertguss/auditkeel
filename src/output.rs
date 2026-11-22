//! Dual-mode human TTY + JSON + token-budgeted agent output emitters.

use owo_colors::OwoColorize;

use crate::cli::ResolvedFormat;
use crate::model::{AuditReport, DiffReport, Severity};

pub fn emit_audit(report: &AuditReport, format: ResolvedFormat) {
    match format {
        ResolvedFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            // Compact, single-object agent envelope with zero ANSI escapes
            println!(
                "{}",
                serde_json::to_string(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Human => emit_audit_human(report),
    }
}

fn emit_audit_human(r: &AuditReport) {
    let status_badge = match r.status.as_str() {
        "pass" => "PASS".green().bold().to_string(),
        "warn" => "WARN".yellow().bold().to_string(),
        _ => "FAIL".red().bold().to_string(),
    };
    println!(
        "{} {} ({}) | sha256: {}",
        "auditkeel".bold(),
        status_badge,
        r.source,
        &r.query_sha256[..12]
    );
    println!(
        "  mode: {} | CTEs: {} | joins: {} | final rows: {}",
        r.mode,
        r.cte_count,
        r.join_count,
        r.final_row_count
            .map(|n| n.to_string())
            .unwrap_or_else(|| "(static)".to_string())
    );

    if !r.waterfall.is_empty() {
        println!("\n{}", "CTE Row-Count Waterfall:".bold());
        println!(
            "  {:<28} {:>10} {:>10} {:>8}",
            "Step", "Rows", "Ratio", "Time"
        );
        for step in &r.waterfall {
            let ratio_str = step
                .ratio_vs_prev
                .map(|v| format!("{v:.2}x"))
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  {:<28} {:>10} {:>10} {:>6}ms",
                step.name, step.row_count, ratio_str, step.elapsed_ms
            );
        }
    }

    if !r.joins.is_empty() {
        println!("\n{}", "Join Cardinality & Coverage:".bold());
        for j in &r.joins {
            if let Some(err) = &j.probe_error {
                println!(
                    "  [{}] {} {} -> {}: {}",
                    j.scope, j.join_type, j.left_relation, j.right_relation, err
                );
                continue;
            }
            println!(
                "  [{}] {} {} -> {} ON {}={}: fanout={:.2}x | matched={:.1}% | right_dups={:.1}% (max {})",
                j.scope,
                j.join_type,
                j.left_relation,
                j.right_relation,
                j.left_key,
                j.right_key,
                j.fanout_factor.unwrap_or(1.0),
                j.matched_left_pct.unwrap_or(0.0),
                j.right_dup_key_pct.unwrap_or(0.0),
                j.right_max_dupes.unwrap_or(0)
            );
            if !j.sample_unmatched_keys.is_empty() {
                println!(
                    "      sample unmatched left keys: {}",
                    j.sample_unmatched_keys.join(", ")
                );
            }
        }
    }

    if let Some(g) = &r.grain {
        println!("\n{}", "Entity Grain Verification:".bold());
        let tag = if g.is_unique {
            "UNIQUE".green().bold().to_string()
        } else {
            "DUPLICATES FOUND".red().bold().to_string()
        };
        println!(
            "  key=({}) -> {} | rows={} distinct={} dupes={} nulls={}",
            g.key_columns.join(", "),
            tag,
            g.total_rows,
            g.distinct_keys,
            g.duplicate_rows,
            g.null_key_rows
        );
        if !g.sample_duplicate_keys.is_empty() {
            println!(
                "  sample duplicate keys: {}",
                g.sample_duplicate_keys.join(", ")
            );
        }
        if !g.spot_checks.is_empty() {
            println!("  spot-check entity traces:");
            for sc in &g.spot_checks {
                let flow: Vec<String> = sc
                    .cte_counts
                    .iter()
                    .map(|(c, n)| format!("{c}:{n}"))
                    .collect();
                println!("    key={} -> {}", sc.key_value, flow.join(" -> "));
            }
        }
    }

    if r.findings.is_empty() {
        println!("\n{}", "Findings: none (clean audit)".green());
    } else {
        println!("\n{} ({}):", "Findings".bold(), r.findings.len());
        for f in &r.findings {
            let sev = match f.severity {
                Severity::Error => "ERROR".red().bold().to_string(),
                Severity::Warn => "WARN".yellow().bold().to_string(),
                Severity::Info => "INFO".cyan().bold().to_string(),
            };
            println!("  [{sev}] {} ({}): {}", f.code, f.location, f.message);
            println!("         fix: {}", f.fix_hint);
        }
    }
}

pub fn emit_diff(report: &DiffReport, format: ResolvedFormat) {
    match format {
        ResolvedFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            println!(
                "{}",
                serde_json::to_string(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Human => {
            let badge = if report.has_drift {
                "DRIFT DETECTED".yellow().bold().to_string()
            } else {
                "IDENTICAL".green().bold().to_string()
            };
            println!(
                "{} diff {} | {} -> {}",
                "auditkeel".bold(),
                badge,
                report.old_source,
                report.new_source
            );
            println!(
                "  rows: {} -> {} (delta: {:+})",
                report.old_row_count, report.new_row_count, report.row_delta
            );
            if !report.added_columns.is_empty() || !report.removed_columns.is_empty() {
                println!(
                    "  schema: +[{}] -[{}]",
                    report.added_columns.join(", "),
                    report.removed_columns.join(", ")
                );
            }
            if !report.type_diffs.is_empty() {
                let td: Vec<String> = report
                    .type_diffs
                    .iter()
                    .map(|t| format!("{} ({} -> {})", t.column, t.old_type, t.new_type))
                    .collect();
                println!("  type changes: {}", td.join(", "));
            }
            if let Some(k) = &report.key_overlap {
                println!(
                    "  keys ({}): in_both={} | only_in_old={} | only_in_new={}",
                    k.key_columns.join(", "),
                    k.in_both,
                    k.only_in_old,
                    k.only_in_new
                );
            }
            if !report.numeric_diffs.is_empty() {
                println!("  numeric aggregate sums:");
                for d in &report.numeric_diffs {
                    println!(
                        "    {:<24} old={:?} new={:?} delta={:?} nulls={}->{}",
                        d.column, d.old_sum, d.new_sum, d.sum_delta, d.old_nulls, d.new_nulls
                    );
                }
            }
        }
    }
}

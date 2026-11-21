//! Self-contained, zero-CDN offline HTML Proof-Carrying Audit & Diff Receipts.

use crate::model::{AuditReport, DiffReport, Severity};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render_audit_html(r: &AuditReport) -> String {
    let max_rows = r
        .waterfall
        .iter()
        .map(|w| w.row_count)
        .max()
        .unwrap_or(1)
        .max(1);

    let mut wf_svg = String::new();
    let row_h = 34;
    let svg_h = 30 + r.waterfall.len() * row_h;
    wf_svg.push_str(&format!(
        "<svg viewBox=\"0 0 680 {svg_h}\" width=\"100%\" role=\"img\" aria-label=\"CTE Waterfall\">"
    ));
    for (idx, step) in r.waterfall.iter().enumerate() {
        let y = 22 + idx * row_h;
        let w = ((step.row_count as f64 / max_rows as f64) * 320.0).max(4.0);
        let fill = if step.row_count == 0 {
            "#c53030"
        } else if step.ratio_vs_prev.is_some_and(|rv| rv > 1.02) {
            "#c05621"
        } else {
            "#1d4ed8"
        };
        let ratio = step
            .ratio_vs_prev
            .map(|v| format!("{v:.2}x"))
            .unwrap_or_else(|| "start".to_string());
        wf_svg.push_str(&format!(
            "<text x=\"0\" y=\"{}\" font-size=\"12\" font-weight=\"600\" fill=\"#102a43\">{}</text>",
            y + 14,
            esc(&step.name)
        ));
        wf_svg.push_str(&format!(
            "<rect x=\"190\" y=\"{}\" width=\"320\" height=\"16\" rx=\"4\" fill=\"#eef2f7\"/>",
            y + 2
        ));
        wf_svg.push_str(&format!(
            "<rect x=\"190\" y=\"{}\" width=\"{w:.1}\" height=\"16\" rx=\"4\" fill=\"{fill}\"/>",
            y + 2
        ));
        wf_svg.push_str(&format!(
            "<text x=\"520\" y=\"{}\" font-size=\"12\" font-weight=\"700\" fill=\"#102a43\">{} ({})</text>",
            y + 14,
            step.row_count,
            esc(&ratio)
        ));
    }
    wf_svg.push_str("</svg>");

    let join_rows: String = r
        .joins
        .iter()
        .map(|j| {
            format!(
                "<tr><td>{}</td><td><strong>{}</strong></td><td>{} &rarr; {}</td><td>{} = {}</td><td><strong>{:.2}x</strong></td><td>{:.1}%</td><td>{:.1}% (max {})</td></tr>",
                esc(&j.scope),
                esc(&j.join_type),
                esc(&j.left_relation),
                esc(&j.right_relation),
                esc(&j.left_key),
                esc(&j.right_key),
                j.fanout_factor.unwrap_or(1.0),
                j.matched_left_pct.unwrap_or(0.0),
                j.right_dup_key_pct.unwrap_or(0.0),
                j.right_max_dupes.unwrap_or(0),
            )
        })
        .collect();

    let findings_html: String = if r.findings.is_empty() {
        "<p style=\"color:#15803d;font-weight:700\">All static &amp; live audit checks passed cleanly.</p>".to_string()
    } else {
        r.findings
            .iter()
            .map(|f| {
                let (bg, fg, lbl) = match f.severity {
                    Severity::Error => ("#fff5f5", "#c53030", "ERROR"),
                    Severity::Warn => ("#fffaf0", "#c05621", "WARN"),
                    Severity::Info => ("#f0f9ff", "#0369a1", "INFO"),
                };
                format!(
                    "<div style=\"border-left:4px solid {fg};background:{bg};padding:10px 14px;border-radius:0 8px 8px 0;margin:8px 0\"><div><strong style=\"color:{fg}\">[{lbl}] {}</strong> <span style=\"color:#52667a\">({})</span></div><div style=\"margin-top:4px\">{}</div><div style=\"margin-top:4px;font-size:0.84rem;color:#52667a\"><strong>Fix:</strong> {}</div></div>",
                    esc(&f.code),
                    esc(&f.location),
                    esc(&f.message),
                    esc(&f.fix_hint)
                )
            })
            .collect()
    };

    let grain_html = r
        .grain
        .as_ref()
        .map(|g| {
            let traces: String = g
                .spot_checks
                .iter()
                .map(|t| {
                    let flow: Vec<String> = t
                        .cte_counts
                        .iter()
                        .map(|(c, n)| format!("{} ({})", esc(c), n))
                        .collect();
                    format!(
                        "<li><code>{}</code>: {}</li>",
                        esc(&t.key_value),
                        flow.join(" &rarr; ")
                    )
                })
                .collect();
            format!(
                "<div class=\"card\"><h2>Entity Grain &amp; Spot-Check Receipts</h2><p>Key: <code>{}</code> &middot; Status: <strong>{}</strong> &middot; Rows: {} &middot; Distinct: {} &middot; Dupes: {}</p><ul>{}</ul></div>",
                esc(&g.key_columns.join(", ")),
                if g.is_unique { "UNIQUE" } else { "DUPLICATES FOUND" },
                g.total_rows,
                g.distinct_keys,
                g.duplicate_rows,
                traces
            )
        })
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>auditkeel Proof-Carrying SQL Receipt — {src}</title>
<style>
  body {{ margin:0; font-family:ui-sans-serif,system-ui,sans-serif; background:#f6f8fb; color:#102a43; line-height:1.5; }}
  .bar {{ background:#142c4c; color:#f8fafc; padding:10px 22px; font-size:0.84rem; display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:22px 18px 48px; }}
  .card {{ background:#fff; border:1px solid #d9e2ec; border-radius:12px; padding:18px 20px; margin-bottom:16px; }}
  h1 {{ margin:0 0 4px; font-size:1.45rem; }} h2 {{ margin:0 0 10px; font-size:1.08rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.86rem; }}
  th, td {{ text-align:left; padding:8px; border-bottom:1px solid #d9e2ec; }}
  th {{ font-size:0.74rem; text-transform:uppercase; color:#52667a; }}
</style>
</head>
<body>
<div class="bar">
  <div><strong>auditkeel v{ver}</strong> &mdash; Proof-Carrying SQL Audit Receipt</div>
  <div>SHA-256: <code>{sha}</code> &middot; {ts}</div>
</div>
<div class="wrap">
  <div class="card">
    <h1>SQL Audit Status: {st}</h1>
    <div style="color:#52667a">Source: <code>{src}</code> &middot; CTEs: {ctes} &middot; Joins: {joins} &middot; Final Rows: {frows}</div>
  </div>
  <div class="card"><h2>Findings ({fcnt})</h2>{findings_html}</div>
  <div class="card"><h2>CTE Row-Count Waterfall</h2>{wf_svg}</div>
  <div class="card"><h2>Join Cardinality &amp; Coverage</h2><table><thead><tr><th>Scope</th><th>Type</th><th>Tables</th><th>Keys</th><th>Fan-Out</th><th>Matched %</th><th>Right Dup Keys</th></tr></thead><tbody>{join_rows}</tbody></table></div>
  {grain_html}
</div>
</body>
</html>"#,
        ver = esc(&r.version),
        sha = esc(&r.query_sha256[..16]),
        ts = esc(&r.audited_at.to_rfc3339()),
        st = esc(&r.status.to_uppercase()),
        src = esc(&r.source),
        ctes = r.cte_count,
        joins = r.join_count,
        frows = r
            .final_row_count
            .map(|n| n.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        fcnt = r.findings.len(),
    )
}

pub fn render_diff_html(d: &DiffReport) -> String {
    let num_rows: String = d
        .numeric_diffs
        .iter()
        .map(|n| {
            format!(
                "<tr><td><strong>{}</strong></td><td>{:?}</td><td>{:?}</td><td><strong>{:?}</strong></td><td>{} &rarr; {}</td></tr>",
                esc(&n.column),
                n.old_sum,
                n.new_sum,
                n.sum_delta,
                n.old_nulls,
                n.new_nulls
            )
        })
        .collect();
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" /><title>auditkeel Live SQL Diff Receipt</title>
<style>body{{margin:0;font-family:ui-sans-serif,system-ui,sans-serif;background:#f6f8fb;color:#102a43}}.wrap{{max-width:1000px;margin:0 auto;padding:22px}}.card{{background:#fff;border:1px solid #d9e2ec;border-radius:12px;padding:18px;margin-bottom:16px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:8px;border-bottom:1px solid #d9e2ec}}</style>
</head><body><div class="wrap">
<div class="card"><h1>auditkeel Live SQL Diff: {st}</h1><p>{old} ({oc} rows) &rarr; {new} ({nc} rows, delta {rd:+})</p></div>
<div class="card"><h2>Numeric Column Aggregate Drift</h2><table><thead><tr><th>Column</th><th>Old Sum</th><th>New Sum</th><th>Delta</th><th>Nulls</th></tr></thead><tbody>{num_rows}</tbody></table></div>
</div></body></html>"#,
        st = esc(&d.status.to_uppercase()),
        old = esc(&d.old_source),
        oc = d.old_row_count,
        new = esc(&d.new_source),
        nc = d.new_row_count,
        rd = d.row_delta,
    )
}

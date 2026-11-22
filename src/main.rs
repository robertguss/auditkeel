//! `auditkeel` — Proof-Carrying SQL Analysis Auditor for PostgreSQL (DX + AX).

mod cli;
mod html;
mod model;
mod output;
mod parse;
mod pg;
mod skill;

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use cli::{Cli, Command, FailOn, OutputFormat};
use model::{AuditReport, DiffReport, Finding, Severity};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct AuditRulesFile {
    grain: Option<GrainRules>,
}

#[derive(Debug, Default, Deserialize)]
struct GrainRules {
    #[serde(default)]
    unique_keys: Vec<String>,
    forbid_fanout: Option<bool>,
    min_rows: Option<i64>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn read_sql_input(file: Option<&Path>, sql: Option<&str>) -> Result<(String, String), String> {
    if let Some(s) = sql {
        return Ok(("<inline>".to_string(), s.to_string()));
    }
    if let Some(path) = file {
        if path == Path::new("-") {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read SQL from stdin: {e}"))?;
            return Ok(("<stdin>".to_string(), buf));
        }
        let text = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        return Ok((path.display().to_string(), text));
    }
    Err("provide a SQL file path, `-` for stdin, or `--sql <SQL>`".to_string())
}

fn exit_code_for(findings: &[Finding], fail_on: FailOn) -> u8 {
    match fail_on {
        FailOn::None => 0,
        FailOn::Error => {
            if findings.iter().any(|f| f.severity == Severity::Error) {
                1
            } else {
                0
            }
        }
        FailOn::Warn => {
            if findings
                .iter()
                .any(|f| matches!(f.severity, Severity::Error | Severity::Warn))
            {
                1
            } else {
                0
            }
        }
    }
}

fn dispatch(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Skill { install, format: _ } => {
            skill::handle_skill(install.as_deref())?;
            Ok(0)
        }
        Command::Check {
            file,
            sql,
            format,
            fail_on,
        } => {
            let (source, raw_sql) = read_sql_input(file.as_deref(), sql.as_deref())?;
            let parsed = parse::analyze_sql(&raw_sql)?;
            let report = AuditReport::from_static(&source, &raw_sql, &parsed);
            output::emit_audit(&report, format.resolve());
            Ok(exit_code_for(&report.findings, fail_on))
        }
        Command::Run {
            file,
            sql,
            dsn,
            key,
            rules,
            spot_checks,
            max_fanout,
            html: html_path,
            format,
            fail_on,
        } => {
            let (source, raw_sql) = read_sql_input(file.as_deref(), sql.as_deref())?;
            let parsed = parse::analyze_sql(&raw_sql)?;
            let mut keys: Vec<String> = key
                .as_deref()
                .map(|k| {
                    k.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let mut eff_max_fanout = max_fanout;
            let mut min_rows: Option<i64> = None;

            if let Some(rules_path) = rules {
                let txt = fs::read_to_string(&rules_path)
                    .map_err(|e| format!("failed to read rules {}: {e}", rules_path.display()))?;
                let rf: AuditRulesFile = toml::from_str(&txt)
                    .map_err(|e| format!("failed parsing rules {}: {e}", rules_path.display()))?;
                if let Some(gr) = rf.grain {
                    if keys.is_empty() && !gr.unique_keys.is_empty() {
                        keys = gr.unique_keys;
                    }
                    if gr.forbid_fanout == Some(true) && eff_max_fanout > 1.0 {
                        eff_max_fanout = 1.0001;
                    }
                    min_rows = gr.min_rows;
                }
            }

            let report = pg::run_live_audit(
                &dsn,
                &source,
                &raw_sql,
                &parsed,
                &keys,
                spot_checks,
                eff_max_fanout,
                min_rows,
            )?;
            if let Some(out_html) = html_path {
                let rendered = html::render_audit_html(&report, eff_max_fanout);
                if let Some(parent) = out_html.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create dir {}: {e}", parent.display()))?;
                }
                fs::write(&out_html, rendered)
                    .map_err(|e| format!("failed to write {}: {e}", out_html.display()))?;
                eprintln!("wrote HTML audit receipt: {}", out_html.display());
            }
            output::emit_audit(&report, format.resolve());
            Ok(exit_code_for(&report.findings, fail_on))
        }
        Command::Diff {
            old_file,
            new_file,
            dsn,
            key,
            html: html_path,
            format,
            fail_on_drift,
        } => {
            let old_sql = fs::read_to_string(&old_file)
                .map_err(|e| format!("failed to read {}: {e}", old_file.display()))?;
            let new_sql = fs::read_to_string(&new_file)
                .map_err(|e| format!("failed to read {}: {e}", new_file.display()))?;
            let keys: Vec<String> = key
                .as_deref()
                .map(|k| {
                    k.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let diff: DiffReport = pg::run_live_diff(
                &dsn,
                &old_file.display().to_string(),
                &old_sql,
                &new_file.display().to_string(),
                &new_sql,
                &keys,
            )?;
            if let Some(out_html) = html_path {
                let rendered = html::render_diff_html(&diff);
                if let Some(parent) = out_html.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create dir {}: {e}", parent.display()))?;
                }
                fs::write(&out_html, rendered)
                    .map_err(|e| format!("failed to write {}: {e}", out_html.display()))?;
                eprintln!("wrote HTML diff receipt: {}", out_html.display());
            }
            output::emit_diff(&diff, format.resolve());
            if fail_on_drift && diff.has_drift {
                Ok(1)
            } else {
                Ok(0)
            }
        }
    }
}

#[allow(dead_code)]
fn _keep_output_format(_: OutputFormat) {}

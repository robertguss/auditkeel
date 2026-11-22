use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "auditkeel",
    version,
    about = "Proof-Carrying SQL Analysis Auditor for PostgreSQL (DX + AX)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Auto,
    Human,
    Json,
    Agent,
}

impl OutputFormat {
    pub fn resolve(self) -> ResolvedFormat {
        match self {
            Self::Human => ResolvedFormat::Human,
            Self::Json => ResolvedFormat::Json,
            Self::Agent => ResolvedFormat::Agent,
            Self::Auto => {
                if std::io::stdout().is_terminal() {
                    ResolvedFormat::Human
                } else {
                    ResolvedFormat::Json
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedFormat {
    Human,
    Json,
    Agent,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FailOn {
    Error,
    Warn,
    None,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run read-only live Postgres audit: CTE waterfall, join fan-out/coverage, grain & spot-checks.
    Run {
        /// Path to a .sql file (or `-` to read from stdin).
        file: Option<PathBuf>,

        /// Inline SQL query string (alternative to FILE).
        #[arg(long)]
        sql: Option<String>,

        /// PostgreSQL connection URL (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        dsn: String,

        /// Expected entity grain key column(s), comma-separated (e.g. `student_id` or `sid,tid`).
        #[arg(long)]
        key: Option<String>,

        /// Optional audit rules TOML file (e.g. emitted by `feakeel compile --emit-audit-rules`).
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Number of concrete entity spot-check traces to include when `--key` is set.
        #[arg(long, default_value_t = 3)]
        spot_checks: usize,

        /// Fan-out expansion ratio threshold before raising a FANOUT_SPIKE warning/error.
        #[arg(long, default_value_t = 1.02)]
        max_fanout: f64,

        /// Write a self-contained offline Proof-Carrying HTML Audit Receipt.
        #[arg(long)]
        html: Option<PathBuf>,

        /// Output format: auto (TTY=human, pipe=json), human, json, or agent.
        #[arg(long, value_enum, default_value_t = OutputFormat::Auto)]
        format: OutputFormat,

        /// Exit code 1 threshold: error (default), warn, or none.
        #[arg(long, value_enum, default_value_t = FailOn::Error)]
        fail_on: FailOn,
    },

    /// Fast offline static semantic + CTE DAG + join-graph audit (zero database required).
    Check {
        /// Path to a .sql file (or `-` to read from stdin).
        file: Option<PathBuf>,

        /// Inline SQL query string (alternative to FILE).
        #[arg(long)]
        sql: Option<String>,

        /// Output format: auto, human, json, or agent.
        #[arg(long, value_enum, default_value_t = OutputFormat::Auto)]
        format: OutputFormat,

        /// Exit code 1 threshold: error (default), warn, or none.
        #[arg(long, value_enum, default_value_t = FailOn::Error)]
        fail_on: FailOn,
    },

    /// Live A/B query refactor diff on PostgreSQL (row counts, key overlap, numeric aggregates).
    Diff {
        /// Baseline (old) SQL file.
        old_file: PathBuf,

        /// Candidate (new) SQL file.
        new_file: PathBuf,

        /// PostgreSQL connection URL (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        dsn: String,

        /// Entity key column(s), comma-separated, to compute added/dropped keys.
        #[arg(long)]
        key: Option<String>,

        /// Write a self-contained offline HTML Diff Receipt.
        #[arg(long)]
        html: Option<PathBuf>,

        /// Output format: auto, human, json, or agent.
        #[arg(long, value_enum, default_value_t = OutputFormat::Auto)]
        format: OutputFormat,

        /// Return exit code 1 if row count, key overlap, or numeric aggregates drifted.
        #[arg(long, default_value_t = false)]
        fail_on_drift: bool,
    },

    /// Print or install the bundled SKILL.md manual for AI coding agents.
    Skill {
        /// Install SKILL.md into `<DIR>/auditkeel/SKILL.md` (default `.agents/skills`).
        #[arg(long, num_args = 0..=1, default_missing_value = ".agents/skills")]
        install: Option<PathBuf>,

        /// Output format (accepted for Keel Stack CLI parity).
        #[arg(long, value_enum, default_value_t = OutputFormat::Auto)]
        format: OutputFormat,
    },
}

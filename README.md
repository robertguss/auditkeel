# `auditkeel`

> **Proof-Carrying SQL Analysis Auditor for PostgreSQL (DX + AX)** — Tool #13 in the [Keel Data Stack](https://github.com/robertguss/keel-stack).

Silent analytical bugs (2× join fan-out from duplicate bridge rows, `LEFT JOIN` demoted to `INNER JOIN` by a `WHERE` filter, zero-row CTE collapse, duplicate entity grains, unfiltered soft-deleted rows) **never throw SQL errors** — they quietly produce plausible-looking wrong numbers.

`auditkeel` executes read-only (`BEGIN TRANSACTION READ ONLY`) diagnostic probes against PostgreSQL and emits verifiable **proof-carrying receipts** (terminal, `--format agent` JSON, or zero-CDN `--html` report) before humans or AI agents trust any query result.

## Features

- **CTE Row-Count Waterfall (`auditkeel run`):** Measures exact row counts, expansion/drop ratios, and execution time at every CTE step through `FINAL`, flagging `ZERO_ROW_COLLAPSE` and `CTE_ROW_EXPANSION`.
- **Live Join Cardinality & Fan-Out Probing:** Detects right-table duplicate key %, max duplicates per key, actual fan-out multiplier (catches classic `canvas.pseudonyms` 2× fan-out automatically!), left-match coverage %, and up to 3 sample unmatched keys.
- **Entity Grain Verification & Spot-Check Receipts (`--key`):** Confirms `COUNT(*) == COUNT(DISTINCT key)` on your expected entity grain (e.g., `--key student_id,term_id`) and traces 3 concrete keys step-by-step across every CTE.
- **Live A/B Refactor Diff (`auditkeel diff old.sql new.sql`):** Proves whether a SQL refactor changed row counts, entity key overlap, schema columns, or numeric column `SUM`/null totals.
- **Zero-DB Static Semantic Audit (`auditkeel check`):** Catches `LEFT_JOIN_DEMOTION`, `NOT_IN_NULL_TRAP`, `SOFT_DELETE_UNFILTERED`, and `SELECT_STAR` in milliseconds.
- **Agent-First AX:** Dual-mode TTY/JSON/agent output, strict `stdout`/`stderr` separation, deterministic exit codes (`0` pass, `1` findings/drift, `2` error), and bundled `SKILL.md` (`auditkeel skill --install`).

## Quickstart

```bash
# Install via uv / pip (pre-built wheels) or Cargo
uv tool install auditkeel
# or: cargo install --path .

# 1. Instant offline static semantic check (no DB required)
auditkeel check sql/at_risk_students.sql

# 2. Full read-only live Postgres audit + grain check + offline HTML receipt
auditkeel run sql/at_risk_students.sql \
  --dsn "$DATABASE_URL" \
  --key student_id,term_id \
  --html audit_receipt.html

# 3. Live A/B diff before merging a SQL refactor
auditkeel diff sql/old_mart.sql sql/new_mart.sql \
  --dsn "$DATABASE_URL" \
  --key student_id \
  --fail-on-drift

# 4. Install agent skill into your repo
auditkeel skill --install .agents/skills
```

## License

Dual-licensed under MIT or Apache-2.0.

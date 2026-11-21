---
name: auditkeel
description: Proof-Carrying SQL Analysis Auditor for PostgreSQL. Run before trusting analytics queries, mart refactors, or cross-source joins to verify CTE row waterfalls, join fan-out, match coverage, entity grain uniqueness, and live query diffs.
---

# `auditkeel` — Proof-Carrying SQL Analysis Auditor

## When to Use
- Before reporting numbers from any multi-CTE or cross-source PostgreSQL analytics query.
- Whenever refactoring a SQL view/mart (`auditkeel diff old.sql new.sql --dsn ...`) to prove whether counts, keys, or aggregates shifted.
- To catch silent analytical footguns that do NOT throw SQL errors: 2x join fan-out (e.g., multiple rows per user in a bridge table), `LEFT JOIN` demoted to `INNER JOIN` by `WHERE`, zero-row CTE collapse, grain duplication, or unfiltered soft-deletes.

## Command Matrix

| Task | Command |
| --- | --- |
| Full live read-only audit + CTE waterfall + join probes | `auditkeel run query.sql --dsn "$DATABASE_URL" --key student_id --format agent` |
| Generate shareable offline HTML audit receipt | `auditkeel run query.sql --dsn "$DATABASE_URL" --key student_id --html receipt.html` |
| Offline static semantic + CTE DAG audit (no DB) | `auditkeel check query.sql --format agent` |
| Live A/B query refactor diff (rows, keys, aggregates) | `auditkeel diff old.sql new.sql --dsn "$DATABASE_URL" --key id --format agent` |
| Print/install this skill | `auditkeel skill` / `auditkeel skill --install` |

## Exit Codes
- `0`: Audit passed with no blocking findings.
- `1`: Audit completed, blocking findings detected (e.g., join fan-out, duplicate grain, `LEFT JOIN` demotion, zero-row collapse).
- `2`: Usage, SQL parse, or database connection error.

## Output Contract (`--format agent`)
- Pure JSON on `stdout`; progress/diagnostics strictly on `stderr`.
- Includes `status`, `receipt_sha256`, `waterfall[]` (CTE name, row count, ratio vs prior), `joins[]` (right duplicate key %, match coverage %, fan-out multiplier, sample unmatched keys), `grain` (unique vs duplicate count + 3 spot-check traces), and `findings[]` with `code`, `severity`, `message`, and `fix_hint`.

## Safety
- Every live Postgres query runs inside `BEGIN TRANSACTION READ ONLY` and rolls back immediately — `auditkeel` never mutates database state.

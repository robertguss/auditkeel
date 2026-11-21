//! PostgreSQL SQL AST extraction (CTEs, JOIN specs, static semantic audits).

use std::collections::HashSet;

use sqlparser::ast::{
    BinaryOperator, Expr, InTarget, JoinConstraint, JoinOperator, Query, Select, SetExpr,
    Statement, TableFactor, TableWithJoins,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::model::{Finding, Severity};

#[derive(Debug, Clone)]
pub struct ParsedCte {
    pub name: String,
    pub query_sql: String,
    pub referenced_ctes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedJoin {
    pub scope: String,
    pub join_type: String,
    pub left_relation: String,
    pub left_alias: String,
    pub right_relation: String,
    pub right_alias: String,
    pub left_key_col: String,
    pub right_key_col: String,
}

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub ctes: Vec<ParsedCte>,
    pub full_query_sql: String,
    pub joins: Vec<ParsedJoin>,
    pub static_findings: Vec<Finding>,
}

const SOFT_DELETE_TABLES: &[&str] = &[
    "submissions",
    "courses",
    "pseudonyms",
    "enrollments",
    "assignments",
];

pub fn analyze_sql(raw_sql: &str) -> Result<ParsedQuery, String> {
    let trimmed = raw_sql.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return Err("SQL input is empty".to_string());
    }

    let dialect = PostgreSqlDialect {};
    let stmts = Parser::parse_sql(&dialect, trimmed)
        .map_err(|e| format!("PostgreSQL SQL parse error: {e}"))?;
    if stmts.is_empty() {
        return Err("no SQL statement found".to_string());
    }

    let mut findings: Vec<Finding> = Vec::new();
    if stmts.len() > 1 {
        findings.push(Finding {
            code: "MULTI_STATEMENT".to_string(),
            severity: Severity::Warn,
            location: "input".to_string(),
            message: format!(
                "Found {} statements; auditing the last SELECT/WITH query.",
                stmts.len()
            ),
            fix_hint: "Pass a single SELECT / WITH query file for cleanest CTE auditing."
                .to_string(),
        });
    }

    let query_stmt = stmts
        .iter()
        .rev()
        .find_map(|s| match s {
            Statement::Query(q) => Some(q.as_ref()),
            _ => None,
        })
        .ok_or_else(|| {
            "expected a SELECT / WITH query statement (DDL/DML cannot be audited read-only)"
                .to_string()
        })?;

    let mut ctes = Vec::new();
    let mut joins = Vec::new();
    let mut known_ctes: Vec<String> = Vec::new();

    if let Some(with) = &query_stmt.with {
        for cte in &with.cte_tables {
            let name = cte.alias.name.value.clone();
            let q_sql = cte.query.to_string();
            let refs = find_referenced_ctes(&q_sql, &known_ctes);
            inspect_query(&name, &cte.query, &mut joins, &mut findings);
            ctes.push(ParsedCte {
                name: name.clone(),
                query_sql: q_sql,
                referenced_ctes: refs,
            });
            known_ctes.push(name);
        }
    }

    // Inspect final query body without WITH prefix
    let mut final_only = query_stmt.clone();
    final_only.with = None;
    inspect_query("FINAL", &final_only, &mut joins, &mut findings);

    Ok(ParsedQuery {
        ctes,
        full_query_sql: trimmed.to_string(),
        joins,
        static_findings: findings,
    })
}

fn find_referenced_ctes(sql_text: &str, prior_ctes: &[String]) -> Vec<String> {
    let lower = sql_text.to_lowercase();
    prior_ctes
        .iter()
        .filter(|name| {
            let needle = name.to_lowercase();
            lower
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|tok| tok == needle)
        })
        .cloned()
        .collect()
}

fn inspect_query(
    scope: &str,
    query: &Query,
    joins_out: &mut Vec<ParsedJoin>,
    findings: &mut Vec<Finding>,
) {
    if let SetExpr::Select(sel) = query.body.as_ref() {
        inspect_select(scope, sel, joins_out, findings);
    } else if let SetExpr::SetOperation { left, right, .. } = query.body.as_ref() {
        if let SetExpr::Select(sel) = left.as_ref() {
            inspect_select(scope, sel, joins_out, findings);
        }
        if let SetExpr::Select(sel) = right.as_ref() {
            inspect_select(scope, sel, joins_out, findings);
        }
    }
}

fn table_name_and_alias(factor: &TableFactor) -> Option<(String, String)> {
    match factor {
        TableFactor::Table { name, alias, .. } => {
            let rel = name.to_string();
            let al = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .unwrap_or_else(|| {
                    rel.rsplit('.')
                        .next()
                        .unwrap_or(&rel)
                        .trim_matches('"')
                        .to_string()
                });
            Some((rel, al))
        }
        TableFactor::Derived { alias, .. } => {
            let al = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .unwrap_or_else(|| "subquery".to_string());
            Some((format!("({al})"), al))
        }
        _ => None,
    }
}

fn inspect_select(
    scope: &str,
    sel: &Select,
    joins_out: &mut Vec<ParsedJoin>,
    findings: &mut Vec<Finding>,
) {
    // 1. Check SELECT * in FINAL query
    if scope == "FINAL" {
        for item in &sel.projection {
            if matches!(item, sqlparser::ast::SelectItem::Wildcard(_)) {
                findings.push(Finding {
                    code: "SELECT_STAR".to_string(),
                    severity: Severity::Info,
                    location: scope.to_string(),
                    message: "Final query uses `SELECT *`, which can silently drift columns or leak PII.".to_string(),
                    fix_hint: "Explicitly list output columns in the final SELECT.".to_string(),
                });
                break;
            }
        }
    }

    // 2. Inspect FROM + JOINs
    let mut left_joined_aliases: Vec<(String, String)> = Vec::new();
    let mut referenced_relations: Vec<String> = Vec::new();

    for twj in &sel.from {
        inspect_table_with_joins(
            scope,
            twj,
            &mut left_joined_aliases,
            &mut referenced_relations,
            joins_out,
        );
    }

    // 3. Check WHERE clause for LEFT JOIN demotion + NOT IN null traps + soft-delete filtering
    let where_sql = sel
        .selection
        .as_ref()
        .map(|e| e.to_string().to_lowercase())
        .unwrap_or_default();

    if let Some(where_expr) = &sel.selection {
        check_not_in_subquery(scope, where_expr, findings);
        for (alias, right_rel) in &left_joined_aliases {
            if is_alias_filtered_non_null(where_expr, alias) {
                findings.push(Finding {
                    code: "LEFT_JOIN_DEMOTION".to_string(),
                    severity: Severity::Error,
                    location: scope.to_string(),
                    message: format!(
                        "WHERE clause filters LEFT JOIN alias `{alias}` ({right_rel}) without `IS NULL`, silently turning the LEFT JOIN into an INNER JOIN and dropping unmatched rows."
                    ),
                    fix_hint: format!(
                        "Move the filter on `{alias}` into the `LEFT JOIN ... ON` clause or allow `{alias}.col IS NULL`."
                    ),
                });
            }
        }
    }

    // 4. Warn if known LMS/Canvas soft-delete tables lack a workflow_state/deleted filter
    for rel in &referenced_relations {
        let low = rel.to_lowercase();
        let short = low.rsplit('.').next().unwrap_or(&low).trim_matches('"');
        if low.contains("canvas.")
            && SOFT_DELETE_TABLES.contains(&short)
            && !where_sql.contains("workflow_state")
            && !where_sql.contains("deleted")
        {
            findings.push(Finding {
                code: "SOFT_DELETE_UNFILTERED".to_string(),
                severity: Severity::Warn,
                location: scope.to_string(),
                message: format!(
                    "Canvas table `{rel}` is queried without filtering `workflow_state <> 'deleted'`."
                ),
                fix_hint: format!(
                    "Add `workflow_state <> 'deleted'` (or `workflow_state = 'active'`) on `{rel}`."
                ),
            });
        }
    }
}

fn inspect_table_with_joins(
    scope: &str,
    twj: &TableWithJoins,
    left_joined_aliases: &mut Vec<(String, String)>,
    referenced_relations: &mut Vec<String>,
    joins_out: &mut Vec<ParsedJoin>,
) {
    let Some((base_rel, base_alias)) = table_name_and_alias(&twj.relation) else {
        return;
    };
    referenced_relations.push(base_rel.clone());
    let mut alias_map: Vec<(String, String)> = vec![(base_alias.clone(), base_rel.clone())];

    for join in &twj.joins {
        let Some((right_rel, right_alias)) = table_name_and_alias(&join.relation) else {
            continue;
        };
        referenced_relations.push(right_rel.clone());

        let (jtype, is_left, constraint) = match &join.join_operator {
            JoinOperator::Inner(c) | JoinOperator::Join(c) => ("INNER JOIN", false, Some(c)),
            JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => ("LEFT JOIN", true, Some(c)),
            JoinOperator::Right(c) | JoinOperator::RightOuter(c) => ("RIGHT JOIN", false, Some(c)),
            JoinOperator::FullOuter(c) => ("FULL OUTER JOIN", false, Some(c)),
            _ => ("CROSS/OTHER JOIN", false, None),
        };

        if is_left {
            left_joined_aliases.push((right_alias.clone(), right_rel.clone()));
        }

        if let Some(JoinConstraint::On(expr)) = constraint {
            let mut eq_pairs = Vec::new();
            collect_eq_pairs(expr, &mut eq_pairs);
            for (l_al, l_col, r_al, r_col) in eq_pairs {
                if r_al.eq_ignore_ascii_case(&right_alias) {
                    let left_rel = alias_map
                        .iter()
                        .find(|(a, _)| a.eq_ignore_ascii_case(&l_al))
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(|| base_rel.clone());
                    joins_out.push(ParsedJoin {
                        scope: scope.to_string(),
                        join_type: jtype.to_string(),
                        left_relation: left_rel,
                        left_alias: l_al,
                        right_relation: right_rel.clone(),
                        right_alias: right_alias.clone(),
                        left_key_col: l_col,
                        right_key_col: r_col,
                    });
                    break;
                } else if l_al.eq_ignore_ascii_case(&right_alias) {
                    let left_rel = alias_map
                        .iter()
                        .find(|(a, _)| a.eq_ignore_ascii_case(&r_al))
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(|| base_rel.clone());
                    joins_out.push(ParsedJoin {
                        scope: scope.to_string(),
                        join_type: jtype.to_string(),
                        left_relation: left_rel,
                        left_alias: r_al,
                        right_relation: right_rel.clone(),
                        right_alias: right_alias.clone(),
                        left_key_col: r_col,
                        right_key_col: l_col,
                    });
                    break;
                }
            }
        }
        alias_map.push((right_alias, right_rel));
    }
}

fn collect_eq_pairs(expr: &Expr, out: &mut Vec<(String, String, String, String)>) {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            collect_eq_pairs(left, out);
            collect_eq_pairs(right, out);
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            if let (Some((la, lc)), Some((ra, rc))) = (
                extract_qualified_col(left),
                extract_qualified_col(right),
            ) {
                out.push((la, lc, ra, rc));
            }
        }
        Expr::Nested(inner) => collect_eq_pairs(inner, out),
        _ => {}
    }
}

fn extract_qualified_col(expr: &Expr) -> Option<(String, String)> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            let n = parts.len();
            Some((parts[n - 2].value.clone(), parts[n - 1].value.clone()))
        }
        Expr::Cast { expr: inner, .. } => extract_qualified_col(inner),
        Expr::Nested(inner) => extract_qualified_col(inner),
        _ => None,
    }
}

fn check_not_in_subquery(scope: &str, expr: &Expr, findings: &mut Vec<Finding>) {
    match expr {
        Expr::In {
            target: InTarget::Subquery(_),
            negated: true,
            ..
        } => {
            findings.push(Finding {
                code: "NOT_IN_NULL_TRAP".to_string(),
                severity: Severity::Error,
                location: scope.to_string(),
                message: "`NOT IN (SELECT ...)` returns 0 rows if the subquery emits even a single NULL.".to_string(),
                fix_hint: "Rewrite using `NOT EXISTS (SELECT 1 FROM ...)` or filter `IS NOT NULL` inside the subquery.".to_string(),
            });
        }
        Expr::BinaryOp { left, right, .. } => {
            check_not_in_subquery(scope, left, findings);
            check_not_in_subquery(scope, right, findings);
        }
        Expr::Nested(inner) | Expr::UnaryOp { expr: inner, .. } => {
            check_not_in_subquery(scope, inner, findings);
        }
        _ => {}
    }
}

fn is_alias_filtered_non_null(where_expr: &Expr, alias: &str) -> bool {
    let mut positive_terms = Vec::new();
    collect_and_conjuncts(where_expr, &mut positive_terms);
    for term in positive_terms {
        if expr_mentions_alias_strictly(term, alias) {
            return true;
        }
    }
    false
}

fn collect_and_conjuncts<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            collect_and_conjuncts(left, out);
            collect_and_conjuncts(right, out);
        }
        Expr::Nested(inner) => collect_and_conjuncts(inner, out),
        other => out.push(other),
    }
}

fn expr_mentions_alias_strictly(expr: &Expr, alias: &str) -> bool {
    match expr {
        Expr::IsNull(_) | Expr::IsNotNull(_) => false,
        Expr::BinaryOp {
            op: BinaryOperator::Or,
            ..
        } => false,
        Expr::BinaryOp { left, right, .. } => {
            let mut aliases = HashSet::new();
            collect_expr_aliases(left, &mut aliases);
            collect_expr_aliases(right, &mut aliases);
            aliases.iter().any(|a| a.eq_ignore_ascii_case(alias))
        }
        Expr::In { expr: inner, .. } => {
            let mut aliases = HashSet::new();
            collect_expr_aliases(inner, &mut aliases);
            aliases.iter().any(|a| a.eq_ignore_ascii_case(alias))
        }
        _ => false,
    }
}

fn collect_expr_aliases(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            out.insert(parts[parts.len() - 2].value.clone());
        }
        Expr::Cast { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::UnaryOp { expr: inner, .. } => collect_expr_aliases(inner, out),
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_aliases(left, out);
            collect_expr_aliases(right, out);
        }
        _ => {}
    }
}

//! PostgreSQL SQL AST extraction (CTEs, composite JOIN specs, recursive static audits).

use std::collections::HashSet;

use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, InTarget,
    JoinConstraint, JoinOperator, Query, Select, SelectItem, SetExpr, Statement, TableFactor,
    TableWithJoins,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::model::{Finding, Severity};

#[derive(Debug, Clone)]
pub struct ParsedCte {
    pub name: String,
    pub alias_columns: Vec<String>,
    pub query_sql: String,
    pub referenced_ctes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedJoin {
    pub scope: String,
    pub join_type: String,
    pub is_right: bool,
    pub left_relation: String,
    #[allow(dead_code)]
    pub left_alias: String,
    pub right_relation: String,
    #[allow(dead_code)]
    pub right_alias: String,
    pub left_key_cols: Vec<String>,
    pub right_key_cols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub with_recursive: bool,
    pub ctes: Vec<ParsedCte>,
    pub final_referenced_ctes: Vec<String>,
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
    let mut with_recursive = false;

    if let Some(with) = &query_stmt.with {
        with_recursive = with.recursive;
        for cte in &with.cte_tables {
            let name = cte.alias.name.value.clone();
            let alias_columns = cte
                .alias
                .columns
                .iter()
                .map(|c| c.name.value.clone())
                .collect();
            let q_sql = cte.query.to_string();
            let refs = find_referenced_ctes_ast(&cte.query, &known_ctes);
            inspect_query(&name, &cte.query, &mut joins, &mut findings);
            ctes.push(ParsedCte {
                name: name.clone(),
                alias_columns,
                query_sql: q_sql,
                referenced_ctes: refs,
            });
            known_ctes.push(name);
        }
    }

    // Inspect final query body without WITH prefix
    let mut final_only = query_stmt.clone();
    final_only.with = None;
    let final_referenced_ctes = find_referenced_ctes_ast(&final_only, &known_ctes);
    inspect_query("FINAL", &final_only, &mut joins, &mut findings);

    Ok(ParsedQuery {
        with_recursive,
        ctes,
        final_referenced_ctes,
        // Use AST-serialized single query so multi-statements & trailing comments never break wrapping
        full_query_sql: query_stmt.to_string(),
        joins,
        static_findings: findings,
    })
}

fn find_referenced_ctes_ast(query: &Query, prior_ctes: &[String]) -> Vec<String> {
    let mut tables = HashSet::new();
    collect_query_table_names(query, &mut tables);
    prior_ctes
        .iter()
        .filter(|name| tables.contains(&name.to_lowercase()))
        .cloned()
        .collect()
}

fn collect_query_table_names(query: &Query, out: &mut HashSet<String>) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            collect_query_table_names(&cte.query, out);
        }
    }
    collect_set_expr_table_names(query.body.as_ref(), out);
}

fn collect_set_expr_table_names(body: &SetExpr, out: &mut HashSet<String>) {
    match body {
        SetExpr::Select(sel) => {
            for twj in &sel.from {
                collect_factor_table_names(&twj.relation, out);
                for j in &twj.joins {
                    collect_factor_table_names(&j.relation, out);
                }
            }
            if let Some(sel_expr) = &sel.selection {
                collect_expr_subquery_tables(sel_expr, out);
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            collect_set_expr_table_names(left, out);
            collect_set_expr_table_names(right, out);
        }
        SetExpr::Query(q) => collect_query_table_names(q, out),
        _ => {}
    }
}

fn collect_factor_table_names(factor: &TableFactor, out: &mut HashSet<String>) {
    match factor {
        TableFactor::Table { name, .. } => {
            if name.0.len() == 1
                && let Some(ident) = name.0[0].as_ident()
            {
                out.insert(ident.value.to_lowercase());
            }
        }
        TableFactor::Derived { subquery, .. } => collect_query_table_names(subquery, out),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            collect_factor_table_names(&table_with_joins.relation, out);
            for j in &table_with_joins.joins {
                collect_factor_table_names(&j.relation, out);
            }
        }
        _ => {}
    }
}

fn collect_expr_subquery_tables(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Subquery(q) | Expr::Exists { subquery: q, .. } => collect_query_table_names(q, out),
        Expr::In {
            expr: inner,
            target,
            ..
        } => {
            collect_expr_subquery_tables(inner, out);
            if let InTarget::Subquery(q) = target {
                collect_query_table_names(q, out);
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_subquery_tables(left, out);
            collect_expr_subquery_tables(right, out);
        }
        Expr::Nested(inner) | Expr::UnaryOp { expr: inner, .. } => {
            collect_expr_subquery_tables(inner, out);
        }
        _ => {}
    }
}

fn inspect_query(
    scope: &str,
    query: &Query,
    joins_out: &mut Vec<ParsedJoin>,
    findings: &mut Vec<Finding>,
) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            let sub_scope = format!("{scope}.{}", cte.alias.name.value);
            inspect_query(&sub_scope, &cte.query, joins_out, findings);
        }
    }
    inspect_set_expr(scope, query.body.as_ref(), joins_out, findings);
}

fn inspect_set_expr(
    scope: &str,
    body: &SetExpr,
    joins_out: &mut Vec<ParsedJoin>,
    findings: &mut Vec<Finding>,
) {
    match body {
        SetExpr::Select(sel) => inspect_select(scope, sel, joins_out, findings),
        SetExpr::SetOperation { left, right, .. } => {
            inspect_set_expr(scope, left, joins_out, findings);
            inspect_set_expr(scope, right, joins_out, findings);
        }
        SetExpr::Query(q) => inspect_query(scope, q, joins_out, findings),
        _ => {}
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
    // 1. Check SELECT * / s.* in FINAL query
    if scope == "FINAL" {
        for item in &sel.projection {
            if matches!(
                item,
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _)
            ) {
                findings.push(Finding {
                    code: "SELECT_STAR".to_string(),
                    severity: Severity::Info,
                    location: scope.to_string(),
                    message: "Final query uses `SELECT *` (or `alias.*`), which can silently drift columns or leak PII.".to_string(),
                    fix_hint: "Explicitly list output columns in the final SELECT.".to_string(),
                });
                break;
            }
        }
    }

    // 2. Inspect FROM + JOINs (and recurse into derived / LATERAL subqueries!)
    let mut left_joined_aliases: Vec<(String, String)> = Vec::new();
    // (relation, alias, optional JOIN ON sql)
    let mut referenced_relations: Vec<(String, String, String)> = Vec::new();

    for twj in &sel.from {
        inspect_table_with_joins(
            scope,
            twj,
            &mut left_joined_aliases,
            &mut referenced_relations,
            joins_out,
            findings,
        );
    }

    // 3. Check WHERE clause for LEFT JOIN demotion + NOT IN null traps + nested subqueries
    let where_sql = sel
        .selection
        .as_ref()
        .map(|e| e.to_string().to_lowercase())
        .unwrap_or_default();

    if let Some(where_expr) = &sel.selection {
        check_not_in_and_subqueries(scope, where_expr, joins_out, findings);
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

    // 4. Warn if known Canvas soft-delete tables lack a workflow_state/deleted filter
    //    Checking BOTH that table's own JOIN ON clause AND WHERE clause (qualified to its alias when multi-table!)
    let single_table = referenced_relations.len() == 1;
    for (rel, alias, on_sql) in &referenced_relations {
        let low = rel.to_lowercase();
        let short = low.rsplit('.').next().unwrap_or(&low).trim_matches('"');
        if low.contains("canvas.") && SOFT_DELETE_TABLES.contains(&short) {
            let combined = format!("{on_sql} {where_sql}");
            let al_low = alias.to_lowercase();
            let has_filter = if single_table {
                combined.contains("workflow_state") || combined.contains("deleted")
            } else {
                combined.contains(&format!("{al_low}.workflow_state"))
                    || combined.contains(&format!("\"{al_low}\".workflow_state"))
                    || combined.contains(&format!("{al_low}.deleted"))
                    || combined.contains(&format!("\"{al_low}\".deleted"))
                    || on_sql.contains("workflow_state")
                    || on_sql.contains("deleted")
            };
            if !has_filter {
                findings.push(Finding {
                    code: "SOFT_DELETE_UNFILTERED".to_string(),
                    severity: Severity::Warn,
                    location: scope.to_string(),
                    message: format!(
                        "Canvas table `{rel}` (alias `{alias}`) is queried without filtering `workflow_state <> 'deleted'`."
                    ),
                    fix_hint: format!(
                        "Add `{alias}.workflow_state <> 'deleted'` (or `workflow_state = 'active'`) in the JOIN ON or WHERE clause."
                    ),
                });
            }
        }
    }
}

fn inspect_table_with_joins(
    scope: &str,
    twj: &TableWithJoins,
    left_joined_aliases: &mut Vec<(String, String)>,
    referenced_relations: &mut Vec<(String, String, String)>,
    joins_out: &mut Vec<ParsedJoin>,
    findings: &mut Vec<Finding>,
) {
    if let TableFactor::Derived {
        subquery, alias, ..
    } = &twj.relation
    {
        let sub_name = alias
            .as_ref()
            .map(|a| format!("{scope}.{}", a.name.value))
            .unwrap_or_else(|| format!("{scope}.subquery"));
        inspect_query(&sub_name, subquery, joins_out, findings);
    }

    let Some((base_rel, base_alias)) = table_name_and_alias(&twj.relation) else {
        return;
    };
    referenced_relations.push((base_rel.clone(), base_alias.clone(), String::new()));
    let mut alias_map: Vec<(String, String)> = vec![(base_alias.clone(), base_rel.clone())];

    for join in &twj.joins {
        if let TableFactor::Derived {
            subquery, alias, ..
        } = &join.relation
        {
            let sub_name = alias
                .as_ref()
                .map(|a| format!("{scope}.{}", a.name.value))
                .unwrap_or_else(|| format!("{scope}.lateral"));
            inspect_query(&sub_name, subquery, joins_out, findings);
        }

        let Some((right_rel, right_alias)) = table_name_and_alias(&join.relation) else {
            continue;
        };

        let (jtype, is_left, is_right, constraint) = match &join.join_operator {
            JoinOperator::Inner(c) | JoinOperator::Join(c) => ("INNER JOIN", false, false, Some(c)),
            JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => {
                ("LEFT JOIN", true, false, Some(c))
            }
            JoinOperator::Right(c) | JoinOperator::RightOuter(c) => {
                ("RIGHT JOIN", false, true, Some(c))
            }
            JoinOperator::FullOuter(c) => ("FULL OUTER JOIN", false, false, Some(c)),
            _ => ("CROSS/OTHER JOIN", false, false, None),
        };

        let on_sql = match constraint {
            Some(JoinConstraint::On(e)) => e.to_string().to_lowercase(),
            _ => String::new(),
        };
        referenced_relations.push((right_rel.clone(), right_alias.clone(), on_sql));

        if is_left {
            left_joined_aliases.push((right_alias.clone(), right_rel.clone()));
        }

        match constraint {
            Some(JoinConstraint::On(expr)) => {
                let mut eq_pairs = Vec::new();
                collect_eq_pairs(expr, &mut eq_pairs);
                // Collect ALL composite equality conjuncts matching the same left alias & right_alias
                let mut chosen_left_alias: Option<String> = None;
                let mut left_keys: Vec<String> = Vec::new();
                let mut right_keys: Vec<String> = Vec::new();

                for (l_al, l_col, r_al, r_col) in eq_pairs {
                    let matched = if r_al.eq_ignore_ascii_case(&right_alias) {
                        Some((l_al, l_col, r_col))
                    } else if l_al.eq_ignore_ascii_case(&right_alias) {
                        Some((r_al, r_col, l_col))
                    } else {
                        None
                    };
                    if let Some((la, lc, rc)) = matched {
                        match &chosen_left_alias {
                            None => {
                                chosen_left_alias = Some(la);
                                left_keys.push(lc);
                                right_keys.push(rc);
                            }
                            Some(existing) if existing.eq_ignore_ascii_case(&la) => {
                                left_keys.push(lc);
                                right_keys.push(rc);
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(la) = chosen_left_alias {
                    let left_rel = alias_map
                        .iter()
                        .find(|(a, _)| a.eq_ignore_ascii_case(&la))
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(|| base_rel.clone());
                    joins_out.push(ParsedJoin {
                        scope: scope.to_string(),
                        join_type: jtype.to_string(),
                        is_right,
                        left_relation: left_rel,
                        left_alias: la,
                        right_relation: right_rel.clone(),
                        right_alias: right_alias.clone(),
                        left_key_cols: left_keys,
                        right_key_cols: right_keys,
                    });
                }
            }
            Some(JoinConstraint::Using(cols)) if !cols.is_empty() => {
                let key_names: Vec<String> = cols
                    .iter()
                    .filter_map(|c| c.0.last().and_then(|p| p.as_ident()).map(|i| i.value.clone()))
                    .collect();
                if !key_names.is_empty() {
                    joins_out.push(ParsedJoin {
                        scope: scope.to_string(),
                        join_type: jtype.to_string(),
                        is_right,
                        left_relation: base_rel.clone(),
                        left_alias: base_alias.clone(),
                        right_relation: right_rel.clone(),
                        right_alias: right_alias.clone(),
                        left_key_cols: key_names.clone(),
                        right_key_cols: key_names,
                    });
                }
            }
            _ => {}
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

fn check_not_in_and_subqueries(
    scope: &str,
    expr: &Expr,
    joins_out: &mut Vec<ParsedJoin>,
    findings: &mut Vec<Finding>,
) {
    match expr {
        Expr::In {
            expr: inner,
            target: InTarget::Subquery(subq),
            negated,
            ..
        } => {
            if *negated {
                findings.push(Finding {
                    code: "NOT_IN_NULL_TRAP".to_string(),
                    severity: Severity::Error,
                    location: scope.to_string(),
                    message: "`NOT IN (SELECT ...)` returns 0 rows if the subquery emits even a single NULL.".to_string(),
                    fix_hint: "Rewrite using `NOT EXISTS (SELECT 1 FROM ...)` or filter `IS NOT NULL` inside the subquery.".to_string(),
                });
            }
            check_not_in_and_subqueries(scope, inner, joins_out, findings);
            inspect_query(&format!("{scope}.subquery"), subq, joins_out, findings);
        }
        Expr::Subquery(subq) | Expr::Exists { subquery: subq, .. } => {
            inspect_query(&format!("{scope}.subquery"), subq, joins_out, findings);
        }
        Expr::BinaryOp { left, right, .. } => {
            check_not_in_and_subqueries(scope, left, joins_out, findings);
            check_not_in_and_subqueries(scope, right, joins_out, findings);
        }
        Expr::Nested(inner) | Expr::UnaryOp { expr: inner, .. } => {
            check_not_in_and_subqueries(scope, inner, joins_out, findings);
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
        Expr::In { expr: inner, .. }
        | Expr::Like { expr: inner, .. }
        | Expr::ILike { expr: inner, .. }
        | Expr::Between { expr: inner, .. }
        | Expr::UnaryOp { expr: inner, .. } => {
            let mut aliases = HashSet::new();
            collect_expr_aliases(inner, &mut aliases);
            aliases.iter().any(|a| a.eq_ignore_ascii_case(alias))
        }
        Expr::CompoundIdentifier(_) | Expr::Function(_) => {
            let mut aliases = HashSet::new();
            collect_expr_aliases(expr, &mut aliases);
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
        Expr::Function(func) => {
            // Skip COALESCE(..., default) since COALESCE can intentionally survive NULLs
            let fname = func.name.to_string().to_lowercase();
            if fname == "coalesce" {
                return;
            }
            if let FunctionArguments::List(arg_list) = &func.args {
                for arg in &arg_list.args {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e))
                    | FunctionArg::Named {
                        arg: FunctionArgExpr::Expr(e),
                        ..
                    } = arg
                    {
                        collect_expr_aliases(e, out);
                    }
                }
            }
        }
        _ => {}
    }
}

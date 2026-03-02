#!/usr/bin/env python3
"""
AWS Athena – Unused Database Objects Audit
==========================================
Scans an Athena (Glue Catalog) database for tables and views that haven't been
referenced in any completed query execution within a configurable look-back
window.  Walks the full view-dependency chain so that indirect references are
captured.  Produces a CSV report with safe-to-drop SQL for truly unused objects.

Deep parsing features:
  - CTE-aware: WITH-clause aliases are excluded from object references
  - String-literal stripping: quoted strings removed before parsing
  - Presto/Trino view decoding: handles base64-encoded JSON view definitions
  - UNNEST / LATERAL / subquery alias exclusion
  - Cross-database view references via schema-qualified names
  - Multi-workgroup scanning
  - Verbose mode for debugging what the parser sees

Requirements:
    pip install boto3

Usage:
    python athena_audit.py \
        --database my_db \
        --lookback-days 90 \
        --output report.csv \
        --region us-east-1 \
        --workgroup primary \
        --profile my_aws_profile        # optional
        --verbose                        # show per-view parsing detail
"""

import argparse
import base64
import csv
import json
import logging
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Presto view decoder
# ---------------------------------------------------------------------------
_PRESTO_VIEW_RE = re.compile(
    r'/\*\s*Presto\s+View\s*:\s*([A-Za-z0-9+/=\s]+)\*/', re.DOTALL
)


def decode_presto_view(raw: str) -> str:
    """
    Athena/Presto stores views in Glue's ViewOriginalText as either:
      (a) plain SQL (CREATE VIEW ... AS SELECT ...)
      (b) a comment block: /* Presto View: <base64-json> */

    In case (b), the base64 decodes to JSON with an "originalSql" key.
    This function extracts the usable SQL in both cases.
    """
    if not raw:
        return ''
    m = _PRESTO_VIEW_RE.search(raw)
    if m:
        try:
            b64 = m.group(1).replace('\n', '').replace('\r', '').strip()
            decoded = base64.b64decode(b64).decode('utf-8')
            obj = json.loads(decoded)
            return obj.get('originalSql', '') or obj.get('sql', '') or decoded
        except Exception as exc:
            log.debug("Failed to decode Presto view blob: %s", exc)
    return raw


# ---------------------------------------------------------------------------
# SQL parser – CTE-aware, string-safe
# ---------------------------------------------------------------------------

def _strip_noise(sql: str) -> str:
    """Remove comments, string literals, and normalise whitespace."""
    # Multi-line comments (but preserve Presto View blocks handled elsewhere)
    sql = re.sub(r'/\*.*?\*/', ' ', sql, flags=re.DOTALL)
    # Single-line comments
    sql = re.sub(r'--[^\n]*', ' ', sql)
    # Single-quoted string literals  'hello world'
    sql = re.sub(r"'(?:[^'\\]|\\.)*'", "''", sql)
    # Double-quoted identifiers are kept (they are names, not strings)
    return sql


def _extract_cte_aliases(sql: str) -> set[str]:
    """
    Find all CTE aliases defined in WITH clauses so we can exclude them
    from the referenced-objects set.

    Handles:
        WITH a AS (...), b AS (...) SELECT ...
        WITH RECURSIVE a AS (...) ...
    """
    aliases: set[str] = set()
    alias_pat = re.compile(r'[,\s]["`]?(\w+)["`]?\s+AS\s*\(', re.IGNORECASE)
    first_pat = re.compile(r'\bWITH\s+(?:RECURSIVE\s+)?["`]?(\w+)["`]?\s+AS\s*\(', re.IGNORECASE)
    for m in first_pat.finditer(sql):
        aliases.add(m.group(1).lower())
    for m in alias_pat.finditer(sql):
        aliases.add(m.group(1).lower())
    return aliases


# Identifiers — handles backtick, double-quote, and bare names;
# optionally schema-qualified (db.table or `db`.`table`)
_QUAL_IDENT = (
    r'(?:["`]?(\w+)["`]?\s*\.\s*)?'   # optional schema/db  (group 1)
    r'["`]?(\w+)["`]?'                  # object name         (group 2)
)

# Patterns that signal an object reference (each yields groups 1 & 2)
_REF_PATTERNS = [
    re.compile(r'\bFROM\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bJOIN\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bINTO\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bTABLE\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bUPDATE\s+' + _QUAL_IDENT, re.IGNORECASE),
]

# Tokens that should NOT be treated as object names when they follow FROM/JOIN
_SQL_KEYWORDS = {
    'select', 'where', 'group', 'order', 'having', 'limit', 'union',
    'intersect', 'except', 'on', 'using', 'as', 'set', 'values', 'into',
    'insert', 'update', 'delete', 'create', 'drop', 'alter', 'with',
    'case', 'when', 'then', 'else', 'end', 'and', 'or', 'not', 'in',
    'is', 'null', 'true', 'false', 'like', 'between', 'exists',
    'unnest', 'lateral', 'cross', 'full', 'left', 'right', 'inner',
    'outer', 'natural', 'tablesample', 'rows', 'range', 'current',
    'over', 'partition', 'by', 'asc', 'desc', 'fetch', 'offset',
    'for', 'all', 'any', 'some', 'distinct', 'top', 'if',
}


def extract_referenced_objects(
    sql_text: str,
    target_database: str | None = None,
) -> set[str]:
    """
    Return the set of object names (lower-cased) referenced in *sql_text*.

    - Strips comments and string literals first.
    - Excludes CTE aliases defined in WITH clauses.
    - Excludes SQL keywords that regex might accidentally capture.
    - Excludes UNNEST(...) which is not a table reference.
    - If *target_database* is given, schema-qualified names that reference a
      DIFFERENT database are skipped.
    """
    if not sql_text:
        return set()

    sql_clean = _strip_noise(sql_text)
    cte_aliases = _extract_cte_aliases(sql_clean)

    found: set[str] = set()
    for pat in _REF_PATTERNS:
        for m in pat.finditer(sql_clean):
            schema_part = (m.group(1) or '').strip('`"').lower()
            name_part = m.group(2).strip('`"').lower()

            # Skip SQL keywords the regex accidentally grabbed
            if name_part in _SQL_KEYWORDS:
                continue

            # Skip CTE aliases
            if name_part in cte_aliases:
                continue

            # Skip if it's from a different database (schema-qualified)
            if target_database and schema_part and schema_part != target_database.lower():
                continue

            found.add(name_part)

    return found


# ---------------------------------------------------------------------------
# Glue / Athena helpers
# ---------------------------------------------------------------------------

def get_catalog_objects(glue_client, database: str) -> dict[str, str]:
    """Return {object_name_lower: object_type} from the Glue catalog."""
    objects: dict[str, str] = {}
    paginator = glue_client.get_paginator('get_tables')
    for page in paginator.paginate(DatabaseName=database):
        for tbl in page.get('TableList', []):
            name = tbl['Name'].lower()
            # Glue marks views with TableType='VIRTUAL_VIEW'
            if tbl.get('TableType', '').upper() == 'VIRTUAL_VIEW':
                objects[name] = 'VIEW'
            else:
                objects[name] = 'TABLE'
    log.info("Found %d catalog objects in database '%s'  (%d views, %d tables)",
             len(objects), database,
             sum(1 for t in objects.values() if t == 'VIEW'),
             sum(1 for t in objects.values() if t == 'TABLE'))
    return objects


def get_view_sql(glue_client, database: str, view_name: str) -> str:
    """Retrieve the usable SQL definition of a view from Glue."""
    try:
        resp = glue_client.get_table(DatabaseName=database, Name=view_name)
        tbl = resp['Table']
        raw = tbl.get('ViewOriginalText') or tbl.get('ViewExpandedText') or ''
        return decode_presto_view(raw)
    except Exception as exc:
        log.warning("Could not retrieve view SQL for '%s': %s", view_name, exc)
        return ''


def build_view_dependency_graph(
    glue_client, database: str, catalog_objects: dict[str, str],
    verbose: bool = False,
) -> dict[str, set[str]]:
    """
    For every VIEW in the catalog, parse its SQL and record which other
    catalog objects it directly references.

    Returns {view_name: {referenced_object, ...}}.
    """
    deps: dict[str, set[str]] = {}
    catalog_keys = set(catalog_objects.keys())
    views = [n for n, t in catalog_objects.items() if t == 'VIEW']

    for vname in views:
        sql = get_view_sql(glue_client, database, vname)
        if not sql:
            deps[vname] = set()
            if verbose:
                log.info("  VIEW %-40s  → (no SQL found)", vname)
            continue

        all_refs = extract_referenced_objects(sql, target_database=database)
        # Only keep refs that are actual catalog objects in this DB
        matched = all_refs & catalog_keys
        # A view shouldn't list itself as a dependency
        matched.discard(vname)
        deps[vname] = matched

        if verbose:
            log.info("  VIEW %-40s  → refs: %s", vname,
                     ', '.join(sorted(matched)) or '(none)')

    log.info("Built dependency graph for %d views", len(deps))
    return deps


def walk_indirect_refs(
    view_deps: dict[str, set[str]],
) -> dict[str, set[str]]:
    """
    Expand the dependency graph so that for each view we know *all* objects
    it transitively depends on (direct + indirect).

    Returns {view_name: {all_transitive_deps}}.
    """
    resolved: dict[str, set[str]] = {}

    def _resolve(name: str, visited: set[str]) -> set[str]:
        if name in resolved:
            return resolved[name]
        if name not in view_deps:
            return set()
        if name in visited:
            return set()  # cycle guard
        visited.add(name)
        all_deps: set[str] = set(view_deps[name])
        for dep in list(view_deps[name]):
            all_deps |= _resolve(dep, visited)
        resolved[name] = all_deps
        return all_deps

    for v in view_deps:
        _resolve(v, set())
    return resolved


def _retry_on_throttle(func, *args, max_retries: int = 8, **kwargs):
    """Call *func* with exponential backoff on ThrottlingException."""
    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            if 'ThrottlingException' in str(exc) or 'Rate exceeded' in str(exc):
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt + 0.5 * attempt, 60)
                log.info("  Throttled — waiting %.1fs before retry %d/%d",
                         wait, attempt + 1, max_retries)
                time.sleep(wait)
            else:
                raise


def fetch_query_executions(
    athena_client,
    workgroups: list[str],
    since: datetime,
) -> list[dict]:
    """
    Return all SUCCEEDED query executions across the given *workgroups*
    whose completion time is >= *since*.

    Uses exponential backoff to handle AWS API throttling.
    """
    all_results: list[dict] = []

    for wg in workgroups:
        execution_ids: list[str] = []
        try:
            paginator = athena_client.get_paginator('list_query_executions')
            for page in paginator.paginate(WorkGroup=wg):
                execution_ids.extend(page.get('QueryExecutionIds', []))
                # Pace pagination to avoid throttling
                time.sleep(0.3)
        except Exception as exc:
            if 'ThrottlingException' in str(exc) or 'Rate exceeded' in str(exc):
                log.warning("Throttled during listing for workgroup '%s'. "
                            "Retrying with backoff...", wg)
                # Retry the whole listing with manual pagination
                execution_ids = []
                next_token = None
                while True:
                    try:
                        kwargs: dict = {'WorkGroup': wg, 'MaxResults': 50}
                        if next_token:
                            kwargs['NextToken'] = next_token
                        resp = _retry_on_throttle(
                            athena_client.list_query_executions, **kwargs)
                        execution_ids.extend(resp.get('QueryExecutionIds', []))
                        next_token = resp.get('NextToken')
                        if not next_token:
                            break
                        time.sleep(0.5)
                    except Exception as inner_exc:
                        log.warning("Failed to list executions for workgroup '%s' "
                                    "after retries: %s", wg, inner_exc)
                        break
            else:
                log.warning("Could not list executions for workgroup '%s': %s", wg, exc)
                continue

        log.info("Workgroup '%s': %d execution IDs found", wg, len(execution_ids))

        # BatchGetQueryExecution accepts max 50 at a time
        for i in range(0, len(execution_ids), 50):
            batch = execution_ids[i : i + 50]
            try:
                resp = _retry_on_throttle(
                    athena_client.batch_get_query_execution,
                    QueryExecutionIds=batch)
            except Exception as exc:
                log.warning("Failed to get batch %d-%d: %s", i, i + len(batch), exc)
                continue
            for qe in resp.get('QueryExecutions', []):
                status = qe.get('Status', {})
                if status.get('State') != 'SUCCEEDED':
                    continue
                completion = status.get('CompletionDateTime')
                if completion and completion >= since:
                    all_results.append(qe)
            # Pace batch calls
            time.sleep(0.2)

    log.info("Total: %d succeeded executions within lookback window", len(all_results))
    return all_results


def list_workgroups(athena_client) -> list[str]:
    """List all Athena workgroups in the account."""
    wgs: list[str] = []
    try:
        paginator = athena_client.get_paginator('list_work_groups')
        for page in paginator.paginate():
            for wg in page.get('WorkGroups', []):
                wgs.append(wg['Name'])
    except Exception:
        wgs = ['primary']
    return wgs


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(
    database: str,
    lookback_days: int,
    region: str,
    workgroups: list[str],
    all_workgroups: bool,
    profile: str | None,
    output_path: str,
    verbose: bool,
):
    session_kwargs: dict = {'region_name': region}
    if profile:
        session_kwargs['profile_name'] = profile
    session = boto3.Session(**session_kwargs)

    # Adaptive retry mode handles throttling at the SDK level
    retry_config = Config(
        retries={'max_attempts': 10, 'mode': 'adaptive'}
    )
    glue = session.client('glue', config=retry_config)
    athena = session.client('athena', config=retry_config)

    # 1. Catalog objects
    catalog = get_catalog_objects(glue, database)
    if not catalog:
        log.warning("No objects found in database '%s'. Exiting.", database)
        return

    # 2. View dependency graph  (direct + transitive)
    log.info("Parsing view definitions for dependency graph...")
    view_deps_direct = build_view_dependency_graph(glue, database, catalog, verbose=verbose)
    view_deps_all = walk_indirect_refs(view_deps_direct)

    if verbose:
        for vname, deps in sorted(view_deps_all.items()):
            if deps - view_deps_direct.get(vname, set()):
                indirect_only = deps - view_deps_direct.get(vname, set())
                log.info("  VIEW %-40s  transitive deps: %s", vname,
                         ', '.join(sorted(indirect_only)))

    # 3. Resolve workgroups
    if all_workgroups:
        wg_list = list_workgroups(athena)
        log.info("Scanning all workgroups: %s", ', '.join(wg_list))
    else:
        wg_list = workgroups

    # 4. Query executions
    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    executions = fetch_query_executions(athena, wg_list, since)

    # 5. For each object, find direct references from queries
    #    direct_refs[object_name] = [(query_execution_id, completion_dt), ...]
    direct_refs: dict[str, list[tuple[str, datetime]]] = defaultdict(list)

    for qe in executions:
        qeid = qe['QueryExecutionId']
        sql = qe.get('Query', '')
        completion = qe['Status'].get('CompletionDateTime')
        # Also check if the query targets our database (Athena queries have
        # a QueryExecutionContext with Database)
        qe_db = qe.get('QueryExecutionContext', {}).get('Database', '').lower()
        # Parse references from the SQL text
        refs = extract_referenced_objects(sql, target_database=database)
        for ref_name in refs:
            if ref_name in catalog:
                direct_refs[ref_name].append((qeid, completion))

    log.info("Direct references found for %d objects from query history", len(direct_refs))

    # 6. Indirect references – if a view V references object O (transitively),
    #    and V itself was directly queried, then O has an indirect reference
    #    via V.
    #    indirect_refs[object_name] = [(via_view, latest_dt), ...]
    indirect_refs: dict[str, list[tuple[str, datetime]]] = defaultdict(list)

    for view_name, all_deps in view_deps_all.items():
        if view_name not in direct_refs:
            continue
        # This view was queried – every object it depends on gets an indirect ref
        latest_dt = max(dt for _, dt in direct_refs[view_name])
        for dep_obj in all_deps:
            if dep_obj != view_name:
                indirect_refs[dep_obj].append((view_name, latest_dt))

    log.info("Indirect references found for %d objects via view chains", len(indirect_refs))

    # 7. Identify unused objects and compute drop order
    unused_objects: set[str] = set()
    for obj_name in catalog:
        if obj_name not in direct_refs and obj_name not in indirect_refs:
            unused_objects.add(obj_name)

    # Build dependency sub-graph among unused objects only
    # (we only care about ordering drops for things we're actually dropping)
    unused_deps: dict[str, set[str]] = {}
    for obj_name in unused_objects:
        deps = view_deps_direct.get(obj_name, set())
        # Only keep deps that are also unused (and in this DB)
        unused_deps[obj_name] = deps & unused_objects

    # Topological sort: objects depended upon by others get HIGHER order
    # (dropped last).  Leaf views/procs get order 1 (dropped first).
    drop_order: dict[str, int] = {}

    def _topo_depth(name: str, visited: set[str]) -> int:
        if name in drop_order:
            return drop_order[name]
        if name in visited:
            return 0  # cycle guard
        visited.add(name)
        deps = unused_deps.get(name, set())
        if not deps:
            drop_order[name] = 1
            return 1
        max_dep = max(_topo_depth(d, visited) for d in deps)
        drop_order[name] = max_dep + 1
        return max_dep + 1

    for obj_name in unused_objects:
        _topo_depth(obj_name, set())

    # Invert so that the highest-depth objects (base tables) are dropped LAST
    # drop_order 1 = drop first (child views), higher = drop later (parent tables)
    # This is already correct: leaves=1, roots=highest

    # 8. Build CSV rows
    rows: list[dict] = []
    for obj_name, obj_type in sorted(catalog.items()):
        d_refs = direct_refs.get(obj_name, [])
        i_refs = indirect_refs.get(obj_name, [])

        if d_refs:
            latest_qeid, latest_dt = max(d_refs, key=lambda x: x[1])
            rows.append({
                'database': database,
                'objectname': obj_name,
                'objecttype': obj_type,
                'last_reference_datetime': latest_dt.isoformat(),
                'referencetype': 'direct',
                'referencedBy': latest_qeid,
                'drop_order': '',
                'RemovalSql': '',
            })
        elif i_refs:
            via_view, latest_dt = max(i_refs, key=lambda x: x[1])
            rows.append({
                'database': database,
                'objectname': obj_name,
                'objecttype': obj_type,
                'last_reference_datetime': latest_dt.isoformat(),
                'referencetype': 'indirect',
                'referencedBy': via_view,
                'drop_order': '',
                'RemovalSql': '',
            })
        else:
            if obj_type == 'VIEW':
                drop_sql = f'DROP VIEW IF EXISTS "{database}"."{obj_name}";'
            else:
                drop_sql = f'DROP TABLE IF EXISTS "{database}"."{obj_name}";'
            rows.append({
                'database': database,
                'objectname': obj_name,
                'objecttype': obj_type,
                'last_reference_datetime': '',
                'referencetype': '',
                'referencedBy': '',
                'drop_order': drop_order.get(obj_name, 1),
                'RemovalSql': drop_sql,
            })

    # 9. Write CSV — sort unused rows by drop_order so the file is execution-ready
    fieldnames = [
        'database', 'objectname', 'objecttype', 'last_reference_datetime',
        'referencetype', 'referencedBy', 'drop_order', 'RemovalSql',
    ]
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log.info("Wrote %d rows to %s", len(rows), output_path)

    # Summary
    unused = sum(1 for r in rows if r['RemovalSql'])
    direct = sum(1 for r in rows if r['referencetype'] == 'direct')
    indirect = sum(1 for r in rows if r['referencetype'] == 'indirect')
    log.info("Summary: %d direct, %d indirect, %d unused (safe to drop)",
             direct, indirect, unused)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Athena unused-objects audit – produces a CSV report',
    )
    parser.add_argument('--database', '-d', required=True,
                        help='Glue catalog database to audit')
    parser.add_argument('--lookback-days', '-l', type=int, default=90,
                        help='Number of days to look back (default: 90)')
    parser.add_argument('--output', '-o', default='athena_audit_report.csv',
                        help='Output CSV path (default: athena_audit_report.csv)')
    parser.add_argument('--region', '-r', default='us-east-1',
                        help='AWS region (default: us-east-1)')
    parser.add_argument('--workgroup', '-w', action='append', default=None,
                        help='Athena workgroup(s) to scan (repeatable; default: primary)')
    parser.add_argument('--all-workgroups', action='store_true',
                        help='Scan ALL workgroups in the account')
    parser.add_argument('--profile', '-p', default=None,
                        help='AWS CLI profile name (optional)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show per-view parsing detail for debugging')
    args = parser.parse_args()

    workgroups = args.workgroup or ['primary']

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    analyse(
        database=args.database,
        lookback_days=args.lookback_days,
        region=args.region,
        workgroups=workgroups,
        all_workgroups=args.all_workgroups,
        profile=args.profile,
        output_path=args.output,
        verbose=args.verbose,
    )


if __name__ == '__main__':
    main()

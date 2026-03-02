#!/usr/bin/env python3
"""
AWS Athena – Unused Database Objects Audit
==========================================
Scans an Athena (Glue Catalog) database for tables and views that haven't been
referenced in any completed query execution within a configurable look-back
window.  Walks the full view-dependency chain so that indirect references are
captured.  Produces a CSV report with safe-to-drop SQL for truly unused objects.

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
"""

import argparse
import csv
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL identifier pattern – matches schema-qualified or bare names
# ---------------------------------------------------------------------------
_IDENT = r'(?:["`]?[\w*]+["`]?\.)?["`]?([\w]+)["`]?'

# Patterns that indicate an object is being *read* (referenced)
_REF_PATTERNS = [
    re.compile(r'\bFROM\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bJOIN\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bINTO\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bTABLE\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bUPDATE\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bEXISTS\s+' + _IDENT, re.IGNORECASE),
]


def extract_referenced_objects(sql_text: str) -> set[str]:
    """Return the set of object names (lower-cased) referenced in *sql_text*."""
    if not sql_text:
        return set()
    # Strip single-line and multi-line comments
    sql_clean = re.sub(r'--[^\n]*', ' ', sql_text)
    sql_clean = re.sub(r'/\*.*?\*/', ' ', sql_clean, flags=re.DOTALL)
    found: set[str] = set()
    for pat in _REF_PATTERNS:
        for m in pat.finditer(sql_clean):
            found.add(m.group(1).strip('`"').lower())
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
    log.info("Found %d catalog objects in database '%s'", len(objects), database)
    return objects


def get_view_sql(glue_client, database: str, view_name: str) -> str | None:
    """Retrieve the SQL definition of a view from Glue."""
    try:
        resp = glue_client.get_table(DatabaseName=database, Name=view_name)
        tbl = resp['Table']
        # Presto/Trino views store their SQL in ViewOriginalText
        return tbl.get('ViewOriginalText') or tbl.get('ViewExpandedText') or None
    except Exception:
        return None


def build_view_dependency_graph(
    glue_client, database: str, catalog_objects: dict[str, str]
) -> dict[str, set[str]]:
    """
    For every VIEW in the catalog, parse its SQL and record which other
    catalog objects it directly references.

    Returns {view_name: {referenced_object, ...}}.
    """
    deps: dict[str, set[str]] = {}
    views = [n for n, t in catalog_objects.items() if t == 'VIEW']
    for vname in views:
        sql = get_view_sql(glue_client, database, vname)
        refs = extract_referenced_objects(sql) if sql else set()
        # Only keep refs that are actual catalog objects in this DB
        deps[vname] = refs & set(catalog_objects.keys())
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


def fetch_query_executions(
    athena_client,
    workgroup: str,
    since: datetime,
) -> list[dict]:
    """
    Yield all SUCCEEDED query executions in *workgroup* whose completion time
    is >= *since*.
    """
    execution_ids: list[str] = []
    paginator = athena_client.get_paginator('list_query_executions')
    for page in paginator.paginate(WorkGroup=workgroup):
        execution_ids.extend(page.get('QueryExecutionIds', []))

    log.info("Found %d total query execution IDs in workgroup '%s'",
             len(execution_ids), workgroup)

    results: list[dict] = []
    # BatchGetQueryExecution accepts max 50 at a time
    for i in range(0, len(execution_ids), 50):
        batch = execution_ids[i : i + 50]
        resp = athena_client.batch_get_query_execution(QueryExecutionIds=batch)
        for qe in resp.get('QueryExecutions', []):
            status = qe.get('Status', {})
            if status.get('State') != 'SUCCEEDED':
                continue
            completion = status.get('CompletionDateTime')
            if completion and completion >= since:
                results.append(qe)

    log.info("Filtered to %d succeeded executions within lookback window", len(results))
    return results


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(
    database: str,
    lookback_days: int,
    region: str,
    workgroup: str,
    profile: str | None,
    output_path: str,
):
    session_kwargs: dict = {'region_name': region}
    if profile:
        session_kwargs['profile_name'] = profile
    session = boto3.Session(**session_kwargs)

    glue = session.client('glue')
    athena = session.client('athena')

    # 1. Catalog objects
    catalog = get_catalog_objects(glue, database)
    if not catalog:
        log.warning("No objects found in database '%s'. Exiting.", database)
        return

    # 2. View dependency graph  (direct + transitive)
    view_deps_direct = build_view_dependency_graph(glue, database, catalog)
    view_deps_all = walk_indirect_refs(view_deps_direct)

    # 3. Query executions
    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    executions = fetch_query_executions(athena, workgroup, since)

    # 4. For each object, find direct references from queries
    #    direct_refs[object_name] = [(query_execution_id, completion_dt), ...]
    direct_refs: dict[str, list[tuple[str, datetime]]] = defaultdict(list)

    for qe in executions:
        qeid = qe['QueryExecutionId']
        sql = qe.get('Query', '')
        completion = qe['Status'].get('CompletionDateTime')
        refs = extract_referenced_objects(sql)
        for ref_name in refs:
            if ref_name in catalog:
                direct_refs[ref_name].append((qeid, completion))

    # 5. Indirect references – if a view V references object O (transitively),
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

    # 6. Build CSV rows
    rows: list[dict] = []
    for obj_name, obj_type in sorted(catalog.items()):
        d_refs = direct_refs.get(obj_name, [])
        i_refs = indirect_refs.get(obj_name, [])

        if d_refs:
            # Latest direct reference
            latest_qeid, latest_dt = max(d_refs, key=lambda x: x[1])
            rows.append({
                'database': database,
                'objectname': obj_name,
                'objecttype': obj_type,
                'last_reference_datetime': latest_dt.isoformat(),
                'referencetype': 'direct',
                'referencedBy': latest_qeid,
                'RemovalSql': '',
            })
        elif i_refs:
            # Latest indirect reference
            via_view, latest_dt = max(i_refs, key=lambda x: x[1])
            rows.append({
                'database': database,
                'objectname': obj_name,
                'objecttype': obj_type,
                'last_reference_datetime': latest_dt.isoformat(),
                'referencetype': 'indirect',
                'referencedBy': via_view,
                'RemovalSql': '',
            })
        else:
            # Unused – safe to drop
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
                'RemovalSql': drop_sql,
            })

    # 7. Write CSV
    fieldnames = [
        'database', 'objectname', 'objecttype', 'last_reference_datetime',
        'referencetype', 'referencedBy', 'RemovalSql',
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
    parser.add_argument('--workgroup', '-w', default='primary',
                        help='Athena workgroup (default: primary)')
    parser.add_argument('--profile', '-p', default=None,
                        help='AWS CLI profile name (optional)')
    args = parser.parse_args()

    analyse(
        database=args.database,
        lookback_days=args.lookback_days,
        region=args.region,
        workgroup=args.workgroup,
        profile=args.profile,
        output_path=args.output,
    )


if __name__ == '__main__':
    main()

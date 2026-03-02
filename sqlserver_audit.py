#!/usr/bin/env python3
"""
Microsoft SQL Server – Unused Database Objects Audit
=====================================================
Uses Query Store execution history to identify tables, views, stored procedures,
triggers, queues, and functions that haven't been referenced within a
configurable look-back window.  Walks the dependency chain via
sys.sql_expression_dependencies to capture indirect references.  Produces a CSV
report with safe-to-drop SQL for truly unused objects.

Requirements:
    pip install pyodbc

Usage:
    python sqlserver_audit.py \
        --server myserver.database.windows.net \
        --database mydb \
        --username sa \
        --password 'P@ssw0rd' \
        --lookback-days 90 \
        --output report.csv \
        --driver "ODBC Driver 18 for SQL Server"  # optional
"""

import argparse
import csv
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

import pyodbc

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Object types we care about
# ---------------------------------------------------------------------------
# sys.objects type codes → human-readable labels
OBJECT_TYPE_MAP = {
    'U':  'TABLE',
    'V':  'VIEW',
    'P':  'STORED PROCEDURE',
    'FN': 'SCALAR FUNCTION',
    'IF': 'INLINE TABLE FUNCTION',
    'TF': 'TABLE FUNCTION',
    'AF': 'AGGREGATE FUNCTION',
    'TR': 'TRIGGER',
    'SQ': 'SERVICE QUEUE',
}

# SQL identifier pattern (may be schema-qualified)
_IDENT = r'(?:\[?[\w]+\]?\.)*\[?([\w]+)\]?'

_REF_PATTERNS = [
    re.compile(r'\bFROM\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bJOIN\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bINTO\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bUPDATE\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bEXEC(?:UTE)?\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bTABLE\s+' + _IDENT, re.IGNORECASE),
    re.compile(r'\bEXISTS\s+' + _IDENT, re.IGNORECASE),
]


def extract_referenced_objects(sql_text: str) -> set[str]:
    """Return set of object names (lower-cased) referenced in *sql_text*."""
    if not sql_text:
        return set()
    sql_clean = re.sub(r'--[^\n]*', ' ', sql_text)
    sql_clean = re.sub(r'/\*.*?\*/', ' ', sql_clean, flags=re.DOTALL)
    found: set[str] = set()
    for pat in _REF_PATTERNS:
        for m in pat.finditer(sql_clean):
            found.add(m.group(1).strip('[]').lower())
    return found


# ---------------------------------------------------------------------------
# SQL Server helpers
# ---------------------------------------------------------------------------

def connect(server: str, database: str, username: str, password: str,
            driver: str, trusted: bool, port: int) -> pyodbc.Connection:
    if trusted:
        conn_str = (
            f"DRIVER={{{driver}}};"
            f"SERVER={server},{port};"
            f"DATABASE={database};"
            f"Trusted_Connection=yes;"
            f"TrustServerCertificate=yes;"
        )
    else:
        conn_str = (
            f"DRIVER={{{driver}}};"
            f"SERVER={server},{port};"
            f"DATABASE={database};"
            f"UID={username};"
            f"PWD={password};"
            f"TrustServerCertificate=yes;"
        )
    return pyodbc.connect(conn_str)


def get_catalog_objects(conn: pyodbc.Connection) -> dict[str, dict]:
    """
    Return {object_name_lower: {'type': ..., 'schema': ..., 'object_id': ...}}
    for all user objects of the types we audit.
    """
    type_codes = "','".join(OBJECT_TYPE_MAP.keys())
    sql = f"""
        SELECT o.object_id, SCHEMA_NAME(o.schema_id) AS schema_name,
               o.name, o.type
        FROM   sys.objects o
        WHERE  o.type IN ('{type_codes}')
          AND  o.is_ms_shipped = 0
        ORDER  BY o.name
    """
    cur = conn.cursor()
    cur.execute(sql)
    result: dict[str, dict] = {}
    for row in cur.fetchall():
        obj_id, schema, name, type_code = row
        type_code = type_code.strip()
        key = name.lower()
        result[key] = {
            'object_id': obj_id,
            'schema': schema,
            'name': name,           # original casing
            'type_code': type_code,
            'type_label': OBJECT_TYPE_MAP.get(type_code, type_code),
        }
    log.info("Found %d catalog objects", len(result))
    return result


def get_dependency_graph(conn: pyodbc.Connection, catalog: dict) -> dict[str, set[str]]:
    """
    Use sys.sql_expression_dependencies to build a dependency graph.
    Returns {object_name_lower: {referenced_object_lower, ...}}.
    """
    sql = """
        SELECT OBJECT_NAME(d.referencing_id) AS referencing,
               d.referenced_entity_name       AS referenced
        FROM   sys.sql_expression_dependencies d
        WHERE  d.referenced_entity_name IS NOT NULL
    """
    cur = conn.cursor()
    cur.execute(sql)
    deps: dict[str, set[str]] = defaultdict(set)
    catalog_keys = set(catalog.keys())
    for row in cur.fetchall():
        referencing = row.referencing.lower() if row.referencing else None
        referenced = row.referenced.lower() if row.referenced else None
        if referencing and referenced and referencing in catalog_keys and referenced in catalog_keys:
            deps[referencing].add(referenced)
    log.info("Built dependency graph with %d entries", len(deps))
    return dict(deps)


def walk_indirect_refs(deps: dict[str, set[str]]) -> dict[str, set[str]]:
    """Expand transitive dependencies."""
    resolved: dict[str, set[str]] = {}

    def _resolve(name: str, visited: set[str]) -> set[str]:
        if name in resolved:
            return resolved[name]
        if name not in deps:
            return set()
        if name in visited:
            return set()
        visited.add(name)
        all_deps: set[str] = set(deps[name])
        for dep in list(deps[name]):
            all_deps |= _resolve(dep, visited)
        resolved[name] = all_deps
        return all_deps

    for obj in deps:
        _resolve(obj, set())
    return resolved


def fetch_query_store_refs(
    conn: pyodbc.Connection,
    catalog: dict[str, dict],
    since: datetime,
) -> dict[str, list[tuple[str, datetime]]]:
    """
    Query the Query Store for all executed query texts since *since*.
    Parse each text to find object references.

    Returns {object_name_lower: [(query_id_str, last_execution_time), ...]}.
    """
    sql = """
        SELECT q.query_id,
               qt.query_sql_text,
               MAX(rs.last_execution_time) AS last_exec
        FROM   sys.query_store_query q
        JOIN   sys.query_store_query_text qt
               ON q.query_text_id = qt.query_text_id
        JOIN   sys.query_store_plan p
               ON q.query_id = p.query_id
        JOIN   sys.query_store_runtime_stats rs
               ON p.plan_id = rs.plan_id
        WHERE  rs.last_execution_time >= ?
        GROUP  BY q.query_id, qt.query_sql_text
    """
    cur = conn.cursor()
    cur.execute(sql, since)

    refs: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    catalog_keys = set(catalog.keys())
    row_count = 0

    for row in cur.fetchall():
        query_id, sql_text, last_exec = row
        row_count += 1
        obj_names = extract_referenced_objects(sql_text)
        for oname in obj_names:
            if oname in catalog_keys:
                refs[oname].append((str(query_id), last_exec))

    log.info("Scanned %d Query Store entries, found references for %d objects",
             row_count, len(refs))
    return dict(refs)


# ---------------------------------------------------------------------------
# DROP SQL generators
# ---------------------------------------------------------------------------

def removal_sql(schema: str, name: str, type_label: str) -> str:
    """Generate safe DROP statement for the given object type."""
    fqn = f"[{schema}].[{name}]"
    match type_label:
        case 'TABLE':
            return f"DROP TABLE IF EXISTS {fqn};"
        case 'VIEW':
            return f"DROP VIEW IF EXISTS {fqn};"
        case 'STORED PROCEDURE':
            return f"DROP PROCEDURE IF EXISTS {fqn};"
        case 'TRIGGER':
            return f"DROP TRIGGER IF EXISTS {fqn};"
        case 'SERVICE QUEUE':
            # Queues are part of Service Broker – require special handling
            return f"-- Service Broker queue: ALTER QUEUE {fqn} (STATUS = OFF); -- review before dropping"
        case _:
            # Functions (scalar, table-valued, aggregate)
            return f"DROP FUNCTION IF EXISTS {fqn};"


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(
    server: str,
    database: str,
    username: str,
    password: str,
    driver: str,
    trusted: bool,
    port: int,
    lookback_days: int,
    output_path: str,
):
    conn = connect(server, database, username, password, driver, trusted, port)
    log.info("Connected to %s / %s", server, database)

    # 1. Catalog objects
    catalog = get_catalog_objects(conn)
    if not catalog:
        log.warning("No user objects found. Exiting.")
        conn.close()
        return

    # 2. Dependency graph (sys.sql_expression_dependencies)
    deps_direct = get_dependency_graph(conn, catalog)
    deps_all = walk_indirect_refs(deps_direct)

    # 3. Query Store references
    since = datetime.now() - timedelta(days=lookback_days)
    direct_refs = fetch_query_store_refs(conn, catalog, since)

    # 4. Indirect references – if object A was queried directly and A depends
    #    on B (transitively), then B has an indirect reference via A.
    indirect_refs: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for obj_name, all_deps in deps_all.items():
        if obj_name not in direct_refs:
            continue
        latest_dt = max(dt for _, dt in direct_refs[obj_name])
        for dep in all_deps:
            if dep != obj_name:
                indirect_refs[dep].append((obj_name, latest_dt))

    # 5. Build CSV rows
    rows: list[dict] = []
    for obj_name in sorted(catalog):
        info = catalog[obj_name]
        d_refs = direct_refs.get(obj_name, [])
        i_refs = indirect_refs.get(obj_name, [])

        if d_refs:
            qid, latest_dt = max(d_refs, key=lambda x: x[1])
            rows.append({
                'database': database,
                'objectname': info['name'],
                'objecttype': info['type_label'],
                'last_reference_datetime': latest_dt.isoformat(),
                'referencetype': 'direct',
                'referencedBy': f"query_id:{qid}",
                'RemovalSql': '',
            })
        elif i_refs:
            via_obj, latest_dt = max(i_refs, key=lambda x: x[1])
            rows.append({
                'database': database,
                'objectname': info['name'],
                'objecttype': info['type_label'],
                'last_reference_datetime': latest_dt.isoformat(),
                'referencetype': 'indirect',
                'referencedBy': via_obj,
                'RemovalSql': '',
            })
        else:
            drop = removal_sql(info['schema'], info['name'], info['type_label'])
            rows.append({
                'database': database,
                'objectname': info['name'],
                'objecttype': info['type_label'],
                'last_reference_datetime': '',
                'referencetype': '',
                'referencedBy': '',
                'RemovalSql': drop,
            })

    # 6. Write CSV
    fieldnames = [
        'database', 'objectname', 'objecttype', 'last_reference_datetime',
        'referencetype', 'referencedBy', 'RemovalSql',
    ]
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    conn.close()
    log.info("Wrote %d rows to %s", len(rows), output_path)

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
        description='SQL Server unused-objects audit – produces a CSV report',
    )
    parser.add_argument('--server', '-s', required=True,
                        help='SQL Server hostname or IP')
    parser.add_argument('--database', '-d', required=True,
                        help='Database name to audit')
    parser.add_argument('--username', '-u', default='',
                        help='SQL Server username (omit for Windows auth)')
    parser.add_argument('--password', '-P', default='',
                        help='SQL Server password (omit for Windows auth)')
    parser.add_argument('--trusted', '-T', action='store_true',
                        help='Use Windows (trusted) authentication')
    parser.add_argument('--port', type=int, default=1433,
                        help='SQL Server port (default: 1433)')
    parser.add_argument('--driver', default='ODBC Driver 18 for SQL Server',
                        help='ODBC driver name')
    parser.add_argument('--lookback-days', '-l', type=int, default=90,
                        help='Number of days to look back (default: 90)')
    parser.add_argument('--output', '-o', default='sqlserver_audit_report.csv',
                        help='Output CSV path (default: sqlserver_audit_report.csv)')
    args = parser.parse_args()

    analyse(
        server=args.server,
        database=args.database,
        username=args.username,
        password=args.password,
        driver=args.driver,
        trusted=args.trusted,
        port=args.port,
        lookback_days=args.lookback_days,
        output_path=args.output,
    )


if __name__ == '__main__':
    main()

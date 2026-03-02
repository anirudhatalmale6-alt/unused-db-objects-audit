#!/usr/bin/env python3
"""
Microsoft SQL Server – Unused Database Objects Audit
=====================================================
Uses Query Store execution history to identify tables, views, stored procedures,
triggers, queues, and functions that haven't been referenced within a
configurable look-back window.  Walks the dependency chain via
sys.sql_expression_dependencies to capture indirect references.  Produces a CSV
report with safe-to-drop SQL for truly unused objects.

Deep parsing features:
  - CTE-aware: WITH-clause aliases excluded from reference set
  - String-literal stripping: quoted strings removed before parsing
  - Temp table exclusion (#tmp, ##global)
  - sys.sql_expression_dependencies for server-side dependency graph (reliable)
  - Query Store text parsing as secondary confirmation
  - Trigger parent-table awareness (trigger references its parent table)
  - Verbose mode for debugging

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
        --verbose
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

# ---------------------------------------------------------------------------
# SQL parser – CTE-aware, string-safe
# ---------------------------------------------------------------------------

def _strip_noise(sql: str) -> str:
    """Remove comments, string literals, and normalise whitespace."""
    sql = re.sub(r'/\*.*?\*/', ' ', sql, flags=re.DOTALL)
    sql = re.sub(r'--[^\n]*', ' ', sql)
    # Single-quoted strings
    sql = re.sub(r"'(?:[^'\\]|\\.)*'", "''", sql)
    # N'unicode strings'
    sql = re.sub(r"N'(?:[^'\\]|\\.)*'", "''", sql)
    return sql


def _extract_cte_aliases(sql: str) -> set[str]:
    """Extract CTE alias names from WITH clauses."""
    aliases: set[str] = set()
    first_pat = re.compile(
        r'\bWITH\s+(?:RECURSIVE\s+)?\[?(\w+)\]?\s+AS\s*\(', re.IGNORECASE)
    alias_pat = re.compile(r',\s*\[?(\w+)\]?\s+AS\s*\(', re.IGNORECASE)
    for m in first_pat.finditer(sql):
        aliases.add(m.group(1).lower())
    for m in alias_pat.finditer(sql):
        aliases.add(m.group(1).lower())
    return aliases


_QUAL_IDENT = (
    r'(?:\[?(\w+)\]?\s*\.\s*)?'   # optional schema  (group 1)
    r'\[?(\w+)\]?'                  # object name      (group 2)
)

_REF_PATTERNS = [
    re.compile(r'\bFROM\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bJOIN\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bINTO\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bUPDATE\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bEXEC(?:UTE)?\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bTABLE\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bMERGE\s+(?:INTO\s+)?' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bTRUNCATE\s+TABLE\s+' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bINSERT\s+(?:INTO\s+)?' + _QUAL_IDENT, re.IGNORECASE),
    re.compile(r'\bDELETE\s+(?:FROM\s+)?' + _QUAL_IDENT, re.IGNORECASE),
]

_SQL_KEYWORDS = {
    'select', 'where', 'group', 'order', 'having', 'limit', 'union',
    'intersect', 'except', 'on', 'using', 'as', 'set', 'values', 'into',
    'insert', 'update', 'delete', 'create', 'drop', 'alter', 'with',
    'case', 'when', 'then', 'else', 'end', 'and', 'or', 'not', 'in',
    'is', 'null', 'true', 'false', 'like', 'between', 'exists',
    'cross', 'full', 'left', 'right', 'inner', 'outer', 'natural',
    'top', 'distinct', 'all', 'any', 'some', 'if', 'begin', 'return',
    'declare', 'cursor', 'open', 'close', 'fetch', 'next', 'while',
    'break', 'continue', 'goto', 'try', 'catch', 'throw', 'print',
    'raiserror', 'table', 'view', 'procedure', 'function', 'trigger',
    'index', 'nolock', 'rowlock', 'tablock', 'holdlock', 'readpast',
    'output', 'inserted', 'deleted',
}


def extract_referenced_objects(sql_text: str) -> set[str]:
    """
    Return set of object names (lower-cased) referenced in *sql_text*.
    CTE-aware, strips strings/comments, excludes temp tables and keywords.
    """
    if not sql_text:
        return set()
    sql_clean = _strip_noise(sql_text)
    cte_aliases = _extract_cte_aliases(sql_clean)
    found: set[str] = set()
    for pat in _REF_PATTERNS:
        for m in pat.finditer(sql_clean):
            name = m.group(2).strip('[]').lower()
            if name in _SQL_KEYWORDS:
                continue
            if name in cte_aliases:
                continue
            # Skip temp tables
            if name.startswith('#'):
                continue
            found.add(name)
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
               o.name, o.type, o.parent_object_id
        FROM   sys.objects o
        WHERE  o.type IN ('{type_codes}')
          AND  o.is_ms_shipped = 0
        ORDER  BY o.name
    """
    cur = conn.cursor()
    cur.execute(sql)
    result: dict[str, dict] = {}
    for row in cur.fetchall():
        obj_id, schema, name, type_code, parent_id = row
        type_code = type_code.strip()
        key = name.lower()
        result[key] = {
            'object_id': obj_id,
            'schema': schema,
            'name': name,
            'type_code': type_code,
            'type_label': OBJECT_TYPE_MAP.get(type_code, type_code),
            'parent_object_id': parent_id,
        }
    log.info("Found %d catalog objects", len(result))
    for label in set(OBJECT_TYPE_MAP.values()):
        cnt = sum(1 for v in result.values() if v['type_label'] == label)
        if cnt:
            log.info("  %s: %d", label, cnt)
    return result


def get_trigger_parents(conn: pyodbc.Connection, catalog: dict) -> dict[str, str]:
    """
    Return {trigger_name_lower: parent_table_name_lower} for all triggers.
    Triggers fire when their parent table is touched, so if a table is referenced,
    its triggers are implicitly referenced too.
    """
    trigger_parents: dict[str, str] = {}
    # Build object_id → name map
    id_to_name: dict[int, str] = {}
    for name, info in catalog.items():
        id_to_name[info['object_id']] = name
    for name, info in catalog.items():
        if info['type_code'].strip() == 'TR' and info['parent_object_id']:
            parent_name = id_to_name.get(info['parent_object_id'])
            if parent_name:
                trigger_parents[name] = parent_name
    return trigger_parents


def get_dependency_graph(conn: pyodbc.Connection, catalog: dict) -> dict[str, set[str]]:
    """
    Use sys.sql_expression_dependencies to build a dependency graph.
    This is the SERVER-SIDE dependency resolver — much more reliable than
    text parsing for SQL Server.

    Returns {object_name_lower: {referenced_object_lower, ...}}.
    """
    sql = """
        SELECT OBJECT_NAME(d.referencing_id) AS referencing,
               COALESCE(
                   OBJECT_NAME(d.referenced_id),
                   d.referenced_entity_name
               ) AS referenced
        FROM   sys.sql_expression_dependencies d
        WHERE  d.referenced_entity_name IS NOT NULL
           OR  d.referenced_id IS NOT NULL
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
    log.info("Built dependency graph with %d entries (from sys.sql_expression_dependencies)",
             len(deps))
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


def check_query_store_enabled(conn: pyodbc.Connection) -> bool:
    """Check if Query Store is enabled on this database."""
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT actual_state_desc
            FROM   sys.database_query_store_options
        """)
        row = cur.fetchone()
        if row and row[0] in ('READ_WRITE', 'READ_ONLY'):
            log.info("Query Store state: %s", row[0])
            return True
        log.warning("Query Store state: %s", row[0] if row else 'NOT FOUND')
        return False
    except Exception as exc:
        log.warning("Could not check Query Store status: %s", exc)
        return False


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
            return f"-- Service Broker queue: ALTER QUEUE {fqn} (STATUS = OFF); -- review before dropping"
        case _:
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
    verbose: bool,
):
    conn = connect(server, database, username, password, driver, trusted, port)
    log.info("Connected to %s / %s", server, database)

    # 0. Verify Query Store
    if not check_query_store_enabled(conn):
        log.error("Query Store is not enabled on this database. Enable it with:")
        log.error("  ALTER DATABASE [%s] SET QUERY_STORE = ON;", database)
        conn.close()
        sys.exit(1)

    # 1. Catalog objects
    catalog = get_catalog_objects(conn)
    if not catalog:
        log.warning("No user objects found. Exiting.")
        conn.close()
        return

    # 2. Dependency graph (sys.sql_expression_dependencies) — server-side, reliable
    deps_direct = get_dependency_graph(conn, catalog)
    deps_all = walk_indirect_refs(deps_direct)

    if verbose:
        for obj_name, deps in sorted(deps_all.items()):
            log.info("  %-40s depends on: %s", obj_name, ', '.join(sorted(deps)))

    # 2b. Trigger → parent table mapping
    trigger_parents = get_trigger_parents(conn, catalog)
    if trigger_parents:
        log.info("Found %d triggers with parent tables", len(trigger_parents))

    # 3. Query Store references
    since = datetime.now() - timedelta(days=lookback_days)
    direct_refs = fetch_query_store_refs(conn, catalog, since)

    # 3b. If a table is directly referenced, its triggers are indirectly referenced
    trigger_indirect: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for trig_name, parent_name in trigger_parents.items():
        if parent_name in direct_refs:
            latest_dt = max(dt for _, dt in direct_refs[parent_name])
            trigger_indirect[trig_name].append((parent_name, latest_dt))

    # 4. Indirect references via dependency chain
    indirect_refs: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for obj_name, all_deps in deps_all.items():
        if obj_name not in direct_refs:
            continue
        latest_dt = max(dt for _, dt in direct_refs[obj_name])
        for dep in all_deps:
            if dep != obj_name:
                indirect_refs[dep].append((obj_name, latest_dt))

    # Merge trigger-parent indirect refs
    for trig_name, refs in trigger_indirect.items():
        indirect_refs[trig_name].extend(refs)

    log.info("Indirect references found for %d objects", len(indirect_refs))

    # 5. Identify unused objects and compute drop order
    unused_objects: set[str] = set()
    for obj_name in catalog:
        if obj_name not in direct_refs and obj_name not in indirect_refs:
            unused_objects.add(obj_name)

    # Build dependency sub-graph among unused objects only
    unused_deps: dict[str, set[str]] = {}
    for obj_name in unused_objects:
        deps = deps_direct.get(obj_name, set())
        unused_deps[obj_name] = deps & unused_objects

    # Topological sort: leaf objects (depend on others, nothing depends on them)
    # get order 1 (drop first). Base tables/root objects get highest order (drop last).
    drop_order: dict[str, int] = {}

    def _topo_depth(name: str, visited: set[str]) -> int:
        if name in drop_order:
            return drop_order[name]
        if name in visited:
            return 0  # cycle guard
        visited.add(name)
        dep_set = unused_deps.get(name, set())
        if not dep_set:
            drop_order[name] = 1
            return 1
        max_dep = max(_topo_depth(d, visited) for d in dep_set)
        drop_order[name] = max_dep + 1
        return max_dep + 1

    for obj_name in unused_objects:
        _topo_depth(obj_name, set())

    # 6. Build CSV rows
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
                'drop_order': '',
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
                'drop_order': '',
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
                'drop_order': drop_order.get(obj_name, 1),
                'RemovalSql': drop,
            })

    # 7. Write CSV
    fieldnames = [
        'database', 'objectname', 'objecttype', 'last_reference_datetime',
        'referencetype', 'referencedBy', 'drop_order', 'RemovalSql',
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
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show per-object dependency detail')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

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
        verbose=args.verbose,
    )


if __name__ == '__main__':
    main()

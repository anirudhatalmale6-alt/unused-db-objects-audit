# Unused Database Objects Audit

Two Python utilities that flag database objects not referenced within a configurable look-back window and generate safe-to-drop SQL.

## Scripts

### 1. `athena_audit.py` – AWS Athena

Scans a Glue Catalog database, reviews completed Athena query executions, and walks the full view-dependency chain (direct + indirect references via nested views/CTEs).

```bash
pip install boto3

python athena_audit.py \
    --database my_db \
    --lookback-days 90 \
    --output athena_report.csv \
    --region us-east-1 \
    --workgroup primary \
    --profile my_aws_profile   # optional
```

### 2. `sqlserver_audit.py` – Microsoft SQL Server

Uses Query Store execution history and `sys.sql_expression_dependencies` to trace references across tables, views, stored procedures, triggers, queues, and functions.

```bash
pip install pyodbc

# SQL auth
python sqlserver_audit.py \
    --server myserver.database.windows.net \
    --database mydb \
    --username sa \
    --password 'P@ssw0rd' \
    --lookback-days 90 \
    --output sqlserver_report.csv

# Windows auth
python sqlserver_audit.py \
    --server myserver \
    --database mydb \
    --trusted \
    --lookback-days 90
```

## CSV Output Format

Both scripts produce the same CSV layout:

| Column | Description |
|--------|-------------|
| `database` | Database name |
| `objectname` | Object name |
| `objecttype` | TABLE, VIEW, STORED PROCEDURE, etc. |
| `last_reference_datetime` | ISO timestamp of most recent reference |
| `referencetype` | `direct` or `indirect` (blank if unused) |
| `referencedBy` | QueryExecutionId / query_id (direct) or parent object name (indirect) |
| `RemovalSql` | DROP statement — only populated when the object is demonstrably unused |

## Command-Line Parameters

Both scripts accept:
- `--database` / `-d` — Target database name (required)
- `--lookback-days` / `-l` — How many days to look back (default: 90)
- `--output` / `-o` — Output CSV file path

**Athena-specific:**
- `--region` / `-r` — AWS region (default: us-east-1)
- `--workgroup` / `-w` — Athena workgroup (default: primary)
- `--profile` / `-p` — AWS CLI profile name

**SQL Server-specific:**
- `--server` / `-s` — SQL Server hostname (required)
- `--username` / `-u` — SQL auth username
- `--password` / `-P` — SQL auth password
- `--trusted` / `-T` — Use Windows authentication
- `--port` — SQL Server port (default: 1433)
- `--driver` — ODBC driver name (default: ODBC Driver 18 for SQL Server)

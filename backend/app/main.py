import os
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row

SEVERITY_SQL = "(jsonb_path_query_first(raw, '$.containers.cna.metrics[*].cvssV3_1.baseSeverity') #>> '{}')"
SCORE_SQL = "(jsonb_path_query_first(raw, '$.containers.cna.metrics[*].cvssV3_1.baseScore') #>> '{}')::float8"
SUMMARY_COLUMNS = f"cve_id, state, date_updated, title, {SCORE_SQL} AS cvss_score, {SEVERITY_SQL} AS severity"

app = FastAPI(title="ITL CVE Explorer API", version="1.0.0")


def connect() -> psycopg.Connection:
    url = os.environ.get("CVE_DATABASE_URL")
    if not url:
        raise HTTPException(status_code=500, detail="CVE_DATABASE_URL is not set")
    return psycopg.connect(url, row_factory=dict_row)


@app.get("/api/health")
def health() -> dict[str, str]:
    with connect() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    with connect() as conn:
        by_state = conn.execute(
            "SELECT state, count(*) AS count FROM cve_records GROUP BY state ORDER BY state"
        ).fetchall()
        by_severity = conn.execute(
            f"SELECT {SEVERITY_SQL} AS severity, count(*) AS count "
            "FROM cve_records WHERE state = 'PUBLISHED' GROUP BY 1 ORDER BY 2 DESC"
        ).fetchall()
        meta = conn.execute(
            "SELECT max(imported_at) AS last_import, max(date_updated) AS latest_update FROM cve_records"
        ).fetchone()
        recent = conn.execute(
            f"SELECT {SUMMARY_COLUMNS} FROM cve_records ORDER BY date_updated DESC NULLS LAST LIMIT 10"
        ).fetchall()
    return {
        "by_state": by_state,
        "by_severity": by_severity,
        "last_import": meta["last_import"],
        "latest_update": meta["latest_update"],
        "recent": recent,
    }


@app.get("/api/cves")
def list_cves(
    q: str | None = Query(None, max_length=200),
    cve_id: str | None = Query(None, max_length=40),
    state: str | None = Query(None, max_length=20),
    severity: str | None = Query(None, max_length=20),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if cve_id:
        clauses.append("cve_id ILIKE %s")
        params.append(f"%{cve_id.strip()}%")
    if q:
        clauses.append("(title ILIKE %s OR description ILIKE %s)")
        params.extend([f"%{q.strip()}%"] * 2)
    if state:
        clauses.append("state = %s")
        params.append(state.strip().upper())
    if severity:
        clauses.append(f"{SEVERITY_SQL} = %s")
        params.append(severity.strip().upper())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])

    with connect() as conn:
        rows = conn.execute(
            f"SELECT {SUMMARY_COLUMNS}, count(*) OVER() AS total FROM cve_records {where} "
            "ORDER BY date_updated DESC NULLS LAST LIMIT %s OFFSET %s",
            params,
        ).fetchall()

    total = rows[0]["total"] if rows else 0
    items = [{k: v for k, v in row.items() if k != "total"} for row in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute(
            "SELECT cve_id, state, date_updated, imported_at, title, description, raw "
            "FROM cve_records WHERE cve_id = %s",
            (cve_id.strip().upper(),),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return row


STATIC_DIR = Path(os.environ.get("STATIC_DIR", Path(__file__).resolve().parent.parent / "static"))
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

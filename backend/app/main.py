import os
from datetime import date
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from prometheus_fastapi_instrumentator import Instrumentator
from psycopg.rows import dict_row

SEVERITY_SQL = "(jsonb_path_query_first(raw, '$.containers.cna.metrics[*].cvssV3_1.baseSeverity') #>> '{}')"
SCORE_SQL = "(jsonb_path_query_first(raw, '$.containers.cna.metrics[*].cvssV3_1.baseScore') #>> '{}')::float8"
CWE_IDS_SQL = """(
    SELECT COALESCE(array_agg(DISTINCT weakness.cwe_id ORDER BY weakness.cwe_id), ARRAY[]::text[])
    FROM cve_weaknesses AS weakness
    WHERE weakness.cve_id = cve_records.cve_id
)"""
CWE_DETAILS_SQL = """
    COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object(
                'cwe_id', grouped.cwe_id,
                'name', grouped.name,
                'description', grouped.description,
                'status', grouped.status,
                'sources', grouped.sources,
                'cve_descriptions', grouped.cve_descriptions
            ) ORDER BY grouped.cwe_id
        )
        FROM (
            SELECT weakness.cwe_id, catalog.name, catalog.description, catalog.status,
                array_agg(DISTINCT weakness.source ORDER BY weakness.source) AS sources,
                COALESCE(
                    array_agg(DISTINCT weakness.description ORDER BY weakness.description)
                        FILTER (WHERE weakness.description <> ''),
                    ARRAY[]::text[]
                ) AS cve_descriptions
            FROM cve_weaknesses AS weakness
            LEFT JOIN cwe_catalog AS catalog ON catalog.cwe_id = weakness.cwe_id
            WHERE weakness.cve_id = cve_records.cve_id
            GROUP BY weakness.cwe_id, catalog.name, catalog.description, catalog.status
        ) AS grouped
    ), '[]'::jsonb)
"""
SUMMARY_COLUMNS = (
    f"cve_id, state, date_updated, title, {SCORE_SQL} AS cvss_score, {SEVERITY_SQL} AS severity, "
    f"COALESCE(kev, false) AS kev, epss_score, {CWE_IDS_SQL} AS cwe_ids"
)
ENRICHED_FROM = "FROM cve_records LEFT JOIN cve_enrichment USING (cve_id)"

app = FastAPI(title="ITL CVE Explorer API", version="1.0.0")
Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


def connect() -> psycopg.Connection:
    url = os.environ.get("CVE_DATABASE_URL")
    if not url:
        raise HTTPException(status_code=500, detail="CVE_DATABASE_URL is not set")
    return psycopg.connect(url, row_factory=dict_row)


def extract_affected_products(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        return []
    containers = raw.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    affected = cna.get("affected") if isinstance(cna, dict) else None
    if not isinstance(affected, list):
        return []

    products = []
    version_fields = ("version", "lessThan", "lessThanOrEqual", "status", "versionType")
    for product in affected:
        if not isinstance(product, dict):
            continue
        versions = product.get("versions")
        products.append(
            {
                "vendor": product.get("vendor") if isinstance(product.get("vendor"), str) else None,
                "product": product.get("product") if isinstance(product.get("product"), str) else None,
                "platforms": [
                    platform for platform in product.get("platforms", []) if isinstance(platform, str)
                ] if isinstance(product.get("platforms"), list) else [],
                "versions": [
                    {key: version[key] for key in version_fields if isinstance(version.get(key), str)}
                    for version in versions
                    if isinstance(version, dict)
                ] if isinstance(versions, list) else [],
            }
        )
    return products


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
        top_weaknesses = conn.execute(
            "SELECT weakness.cwe_id, catalog.name, count(DISTINCT weakness.cve_id) AS cve_count "
            "FROM cve_weaknesses AS weakness "
            "JOIN cve_records AS record ON record.cve_id = weakness.cve_id "
            "LEFT JOIN cwe_catalog AS catalog ON catalog.cwe_id = weakness.cwe_id "
            "WHERE record.state = 'PUBLISHED' "
            "GROUP BY weakness.cwe_id, catalog.name "
            "ORDER BY cve_count DESC, weakness.cwe_id LIMIT 8"
        ).fetchall()
        meta = conn.execute(
            "SELECT max(imported_at) AS last_import, max(date_updated) AS latest_update FROM cve_records"
        ).fetchone()
        recent = conn.execute(
            f"SELECT {SUMMARY_COLUMNS} {ENRICHED_FROM} ORDER BY date_updated DESC NULLS LAST LIMIT 10"
        ).fetchall()
    return {
        "by_state": by_state,
        "by_severity": by_severity,
        "top_weaknesses": top_weaknesses,
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
    kev: bool | None = Query(None),
    epss_min: float | None = Query(None, ge=0, le=1),
    cwe: str | None = Query(None, max_length=100),
    affected_vendor: str | None = Query(None, max_length=200),
    affected_product: str | None = Query(None, max_length=200),
    affected_platform: str | None = Query(None, max_length=200),
    affected_status: str | None = Query(None, max_length=40),
    cvss_min: float | None = Query(None, ge=0, le=10),
    cvss_max: float | None = Query(None, ge=0, le=10),
    updated_from: date | None = Query(None),
    updated_to: date | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    if cvss_min is not None and cvss_max is not None and cvss_min > cvss_max:
        raise HTTPException(status_code=422, detail="cvss_min must not exceed cvss_max")
    if updated_from is not None and updated_to is not None and updated_from > updated_to:
        raise HTTPException(status_code=422, detail="updated_from must not be after updated_to")

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
    if kev:
        clauses.append("kev = true")
    if epss_min is not None:
        clauses.append("epss_score >= %s")
        params.append(epss_min)
    if cwe:
        term = cwe.strip()
        if term.isdecimal():
            term = f"CWE-{term}"
        normalized_cwe = term.upper()
        if normalized_cwe.startswith("CWE-") and normalized_cwe[4:].isdecimal():
            clauses.append(
                "EXISTS ("
                "SELECT 1 FROM cve_weaknesses AS weakness "
                "WHERE weakness.cve_id = cve_records.cve_id AND weakness.cwe_id = %s)"
            )
            params.append(normalized_cwe)
        else:
            clauses.append(
                "EXISTS ("
                "SELECT 1 FROM cve_weaknesses AS weakness "
                "LEFT JOIN cwe_catalog AS catalog ON catalog.cwe_id = weakness.cwe_id "
                "WHERE weakness.cve_id = cve_records.cve_id "
                "AND catalog.name ILIKE %s)"
            )
            params.append(f"%{term}%")
    affected_conditions = ["affected.cve_id = cve_records.cve_id"]
    for filter_value, column in (
        (affected_vendor, "vendor"),
        (affected_product, "product"),
    ):
        if filter_value and filter_value.strip():
            affected_conditions.append(f"lower(affected.{column}) = lower(%s)")
            params.append(filter_value.strip())
    if affected_platform and affected_platform.strip():
        affected_conditions.append("affected.platforms @> ARRAY[%s]::text[]")
        params.append(affected_platform.strip())
    if affected_status and affected_status.strip():
        affected_conditions.append("lower(affected.version_status) = lower(%s)")
        params.append(affected_status.strip())
    if len(affected_conditions) > 1:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_affected_products AS affected WHERE "
            + " AND ".join(affected_conditions)
            + ")"
        )
    if cvss_min is not None:
        clauses.append(f"{SCORE_SQL} >= %s")
        params.append(cvss_min)
    if cvss_max is not None:
        clauses.append(f"{SCORE_SQL} <= %s")
        params.append(cvss_max)
    if updated_from is not None:
        clauses.append("date_updated >= %s::date")
        params.append(updated_from)
    if updated_to is not None:
        clauses.append("date_updated < %s::date + INTERVAL '1 day'")
        params.append(updated_to)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    page_from = ENRICHED_FROM if kev or epss_min is not None else "FROM cve_records"
    params.extend([limit + 1, offset])

    with connect() as conn:
        rows = conn.execute(
            "WITH page AS MATERIALIZED ("
            "SELECT cve_records.cve_id, cve_records.state, cve_records.date_updated, "
            f"cve_records.title, cve_records.raw {page_from} {where} "
            "ORDER BY date_updated DESC NULLS LAST, cve_id LIMIT %s OFFSET %s"
            ") "
            f"SELECT {SUMMARY_COLUMNS} FROM page AS cve_records "
            "LEFT JOIN cve_enrichment USING (cve_id) "
            "ORDER BY date_updated DESC NULLS LAST, cve_id",
            params,
        ).fetchall()

    has_more = len(rows) > limit
    items = rows[:limit]
    return {"items": items, "has_more": has_more, "limit": limit, "offset": offset}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute(
            "SELECT cve_id, state, date_updated, imported_at, title, description, raw, "
            f"{CWE_DETAILS_SQL} AS weaknesses, "
            "COALESCE(kev, false) AS kev, kev_date_added, kev_due_date, kev_ransomware, "
            "epss_score, epss_percentile, enriched_at "
            f"{ENRICHED_FROM} WHERE cve_id = %s",
            (cve_id.strip().upper(),),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    row["affected_products"] = extract_affected_products(row["raw"])
    return row


NCSC_LINKS_CTE = """
    WITH links AS (
        SELECT advisory.path, cve.cve_id, COALESCE(enrichment.kev, false) AS kev,
               enrichment.epss_score
        FROM ncsc_csaf_cves AS cve
        JOIN ncsc_csaf_documents AS advisory ON advisory.path = cve.path
        LEFT JOIN cve_enrichment AS enrichment ON enrichment.cve_id = cve.cve_id
    )
"""
NCSC_PRIORITY_EPSS = 0.5


@app.get("/api/ncsc/advisories")
def list_ncsc_advisories(
    priority: str = Query("priority", pattern="^(priority|kev|all)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """NCSC advisories, most exploited first.

    priority: `priority` keeps advisories with a KEV or high-EPSS CVE, `kev` keeps KEV only,
    `all` keeps everything.
    """
    filters = {
        "priority": "per_advisory.priority_count > 0",
        "kev": "per_advisory.kev_count > 0",
        "all": "true",
    }
    with connect() as conn:
        summary = conn.execute(
            NCSC_LINKS_CTE
            + """
            SELECT
                (SELECT count(*) FROM ncsc_csaf_documents) AS advisory_count,
                count(DISTINCT cve_id) AS cve_count,
                count(DISTINCT cve_id) FILTER (WHERE kev) AS kev_count,
                count(DISTINCT cve_id) FILTER (WHERE kev OR epss_score >= %s) AS priority_count
            FROM links
            """,
            (NCSC_PRIORITY_EPSS,),
        ).fetchone()
        rows = conn.execute(
            NCSC_LINKS_CTE
            + f"""
            , per_advisory AS (
                SELECT path,
                       count(*) AS cve_count,
                       count(*) FILTER (WHERE kev) AS kev_count,
                       count(*) FILTER (WHERE kev OR epss_score >= %s) AS priority_count,
                       max(epss_score) AS max_epss
                FROM links
                GROUP BY path
            )
            SELECT advisory.tracking_id, advisory.title, advisory.initial_release_date,
                   advisory.current_release_date, per_advisory.cve_count,
                   per_advisory.kev_count, per_advisory.priority_count, per_advisory.max_epss
            FROM ncsc_csaf_documents AS advisory
            JOIN per_advisory USING (path)
            WHERE {filters[priority]}
            ORDER BY advisory.current_release_date DESC NULLS LAST, advisory.tracking_id
            LIMIT %s OFFSET %s
            """,
            (NCSC_PRIORITY_EPSS, limit + 1, offset),
        ).fetchall()
    return {
        "summary": summary,
        "items": rows[:limit],
        "has_more": len(rows) > limit,
        "priority": priority,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/ncsc/advisories/{tracking_id}")
def get_ncsc_advisory(tracking_id: str) -> dict[str, Any]:
    with connect() as conn:
        advisory = conn.execute(
            "SELECT path, tracking_id, title, initial_release_date, current_release_date, "
            "changed_at, imported_at "
            "FROM ncsc_csaf_documents WHERE tracking_id = %s ORDER BY path LIMIT 1",
            (tracking_id.strip().upper(),),
        ).fetchone()
        if advisory is None:
            raise HTTPException(status_code=404, detail=f"{tracking_id} not found")
        cves = conn.execute(
            "SELECT cve.cve_id, record.title, record.state, COALESCE(enrichment.kev, false) AS kev, "
            "enrichment.epss_score "
            "FROM ncsc_csaf_cves AS cve "
            "LEFT JOIN cve_records AS record ON record.cve_id = cve.cve_id "
            "LEFT JOIN cve_enrichment AS enrichment ON enrichment.cve_id = cve.cve_id "
            "WHERE cve.path = %s "
            "ORDER BY kev DESC, enrichment.epss_score DESC NULLS LAST, cve.cve_id",
            (advisory["path"],),
        ).fetchall()
    advisory["link"] = f"https://advisories.ncsc.nl/advisory?id={advisory['tracking_id']}"
    advisory["cves"] = cves
    return advisory


STATIC_DIR = Path(os.environ.get("STATIC_DIR", Path(__file__).resolve().parent.parent / "static"))
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

import type { CveFilters, CveRecord, ListResponse, NcscAdvisoryDetail, NcscListResponse, StatsResponse } from "./types";

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export function fetchStats(): Promise<StatsResponse> {
  return getJson<StatsResponse>("/api/stats");
}

export function fetchCves(filters: CveFilters, limit: number, offset: number): Promise<ListResponse> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  return getJson<ListResponse>(`/api/cves?${params.toString()}`);
}

export function fetchCve(cveId: string): Promise<CveRecord> {
  return getJson<CveRecord>(`/api/cves/${encodeURIComponent(cveId)}`);
}

export function fetchNcscAdvisories(
  priority: "priority" | "kev" | "all",
  limit: number,
  offset: number,
): Promise<NcscListResponse> {
  const params = new URLSearchParams({ priority, limit: String(limit), offset: String(offset) });
  return getJson<NcscListResponse>(`/api/ncsc/advisories?${params.toString()}`);
}

export function fetchNcscAdvisory(trackingId: string): Promise<NcscAdvisoryDetail> {
  return getJson<NcscAdvisoryDetail>(`/api/ncsc/advisories/${encodeURIComponent(trackingId)}`);
}

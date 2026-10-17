export interface CveSummary {
  cve_id: string;
  state: string;
  date_updated: string | null;
  title: string | null;
  cvss_score: number | null;
  severity: string | null;
}

export interface CveRecord {
  cve_id: string;
  state: string;
  date_updated: string | null;
  imported_at: string;
  title: string | null;
  description: string | null;
  raw: unknown;
}

export interface StatsResponse {
  by_state: { state: string; count: number }[];
  by_severity: { severity: string | null; count: number }[];
  last_import: string | null;
  latest_update: string | null;
  recent: CveSummary[];
}

export interface ListResponse {
  items: CveSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface CveFilters {
  q: string;
  cve_id: string;
  state: string;
  severity: string;
}

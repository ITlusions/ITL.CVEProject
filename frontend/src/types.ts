export interface CveSummary {
  cve_id: string;
  state: string;
  date_updated: string | null;
  title: string | null;
  cvss_score: number | null;
  severity: string | null;
  kev: boolean;
  epss_score: number | null;
}

export interface CveRecord {
  cve_id: string;
  state: string;
  date_updated: string | null;
  imported_at: string;
  title: string | null;
  description: string | null;
  raw: unknown;
  kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  enriched_at: string | null;
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
  kev: string;
  epss_min: string;
}

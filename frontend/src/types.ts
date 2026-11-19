export interface CveSummary {
  cve_id: string;
  state: string;
  date_updated: string | null;
  title: string | null;
  cvss_score: number | null;
  severity: string | null;
  kev: boolean;
  epss_score: number | null;
  cwe_ids: string[];
}

export interface CweWeakness {
  cwe_id: string;
  name: string | null;
  description: string | null;
  status: string | null;
  sources: string[];
  cve_descriptions: string[];
}

export interface AffectedVersion {
  version?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  status?: string;
  versionType?: string;
}

export interface AffectedProduct {
  vendor: string | null;
  product: string | null;
  platforms: string[];
  versions: AffectedVersion[];
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
  weaknesses: CweWeakness[];
  affected_products: AffectedProduct[];
}

export interface StatsResponse {
  by_state: { state: string; count: number }[];
  by_severity: { severity: string | null; count: number }[];
  top_weaknesses: { cwe_id: string; name: string | null; cve_count: number }[];
  last_import: string | null;
  latest_update: string | null;
  recent: CveSummary[];
}

export interface ListResponse {
  items: CveSummary[];
  has_more: boolean;
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
  cwe: string;
  affected_vendor: string;
  affected_product: string;
  affected_platform: string;
  affected_status: string;
  cvss_min: string;
  cvss_max: string;
  updated_from: string;
  updated_to: string;
}

export interface NcscSummary {
  advisory_count: number;
  cve_count: number;
  kev_count: number;
  priority_count: number;
}

export interface NcscAdvisory {
  tracking_id: string;
  title: string | null;
  initial_release_date: string | null;
  current_release_date: string | null;
  cve_count: number;
  kev_count: number;
  priority_count: number;
  max_epss: number | null;
}

export interface NcscListResponse {
  summary: NcscSummary;
  items: NcscAdvisory[];
  has_more: boolean;
  priority: "priority" | "kev" | "all";
  limit: number;
  offset: number;
}

export interface NcscAdvisoryCve {
  cve_id: string;
  title: string | null;
  state: string | null;
  kev: boolean;
  epss_score: number | null;
}

export interface NcscAdvisoryDetail {
  tracking_id: string;
  title: string | null;
  initial_release_date: string | null;
  current_release_date: string | null;
  changed_at: string;
  imported_at: string;
  link: string;
  cves: NcscAdvisoryCve[];
}

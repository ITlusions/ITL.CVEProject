import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { fetchCve, fetchCves, fetchStats } from "./api";
import { CveDetail } from "./components/CveDetail";
import { CveTable } from "./components/CveTable";
import { NcscAdvisories } from "./components/NcscAdvisories";
import { StatsBar } from "./components/StatsBar";
import type { CveFilters, CveRecord, ListResponse, StatsResponse } from "./types";

const PAGE_SIZE = 50;
const EMPTY_FILTERS: CveFilters = {
  q: "",
  cve_id: "",
  state: "",
  severity: "",
  kev: "",
  epss_min: "",
  cwe: "",
  affected_vendor: "",
  affected_product: "",
  affected_platform: "",
  affected_status: "",
  cvss_min: "",
  cvss_max: "",
  updated_from: "",
  updated_to: "",
};
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function App() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [statsRequested, setStatsRequested] = useState(false);
  const [draft, setDraft] = useState<CveFilters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<CveFilters>(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);
  const [results, setResults] = useState<ListResponse | null>(null);
  const [selected, setSelected] = useState<CveRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"cves" | "ncsc">("cves");

  useEffect(() => {
    if (!results || statsRequested) return;
    setStatsRequested(true);
    fetchStats().then(setStats).catch((e: Error) => setError(e.message));
  }, [results, statsRequested]);

  useEffect(() => {
    fetchCves(filters, PAGE_SIZE, offset)
      .then((data) => {
        setResults(data);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, [filters, offset]);

  function handleSearch(event: FormEvent) {
    event.preventDefault();
    setOffset(0);
    setFilters(draft);
  }

  function handleReset() {
    setDraft(EMPTY_FILTERS);
    setFilters(EMPTY_FILTERS);
    setOffset(0);
  }

  function handleSelect(cveId: string) {
    fetchCve(cveId)
      .then(setSelected)
      .catch((e: Error) => setError(e.message));
  }

  function handleCweSelect(cweId: string) {
    const nextDraft = { ...draft, cwe: cweId };
    setDraft(nextDraft);
    setFilters({ ...filters, cwe: cweId });
    setOffset(0);
  }

  const itemCount = results?.items.length ?? 0;
  const firstRow = itemCount === 0 ? 0 : offset + 1;
  const lastRow = offset + itemCount;

  return (
    <div className="app">
      <header>
        <h1>ITL CVE Explorer</h1>
        <span className="muted">CVE List V5 import</span>
        <nav className="views">
          <button type="button" className={view === "cves" ? "active" : ""} onClick={() => setView("cves")}>
            CVE explorer
          </button>
          <button type="button" className={view === "ncsc" ? "active" : ""} onClick={() => setView("ncsc")}>
            NCSC advisories
          </button>
        </nav>
      </header>

      {error && <div className="error">{error}</div>}
      {stats && view === "cves" && <StatsBar stats={stats} onSelect={handleSelect} onSelectCwe={handleCweSelect} />}

      <form className="filters" onSubmit={handleSearch} hidden={view !== "cves"}>
        <input
          placeholder="CVE ID (e.g. CVE-2026-1)"
          value={draft.cve_id}
          onChange={(e) => setDraft({ ...draft, cve_id: e.target.value })}
        />
        <input
          placeholder="Keyword in title or description"
          value={draft.q}
          onChange={(e) => setDraft({ ...draft, q: e.target.value })}
        />
        <select value={draft.state} onChange={(e) => setDraft({ ...draft, state: e.target.value })}>
          <option value="">Any state</option>
          <option value="PUBLISHED">Published</option>
          <option value="REJECTED">Rejected</option>
        </select>
        <select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
          <option value="">Any severity</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select value={draft.kev} onChange={(e) => setDraft({ ...draft, kev: e.target.value })}>
          <option value="">Any exploitation status</option>
          <option value="true">Known exploited (KEV)</option>
        </select>
        <input
          type="number"
          min="0"
          max="1"
          step="0.01"
          placeholder="Min EPSS (0-1)"
          value={draft.epss_min}
          onChange={(e) => setDraft({ ...draft, epss_min: e.target.value })}
        />
        <input
          placeholder="CWE ID or weakness name"
          value={draft.cwe}
          onChange={(e) => setDraft({ ...draft, cwe: e.target.value })}
        />
        <details className="advanced-filters">
          <summary>Advanced filters</summary>
          <div className="advanced-filter-grid">
            <label>
              Affected vendor (exact)
              <input
                value={draft.affected_vendor}
                onChange={(e) => setDraft({ ...draft, affected_vendor: e.target.value })}
              />
            </label>
            <label>
              Affected product (exact)
              <input
                value={draft.affected_product}
                onChange={(e) => setDraft({ ...draft, affected_product: e.target.value })}
              />
            </label>
            <label>
              Affected platform (exact)
              <input
                value={draft.affected_platform}
                onChange={(e) => setDraft({ ...draft, affected_platform: e.target.value })}
              />
            </label>
            <label>
              Affected status
              <select
                value={draft.affected_status}
                onChange={(e) => setDraft({ ...draft, affected_status: e.target.value })}
              >
                <option value="">Any status</option>
                <option value="affected">Affected</option>
                <option value="unaffected">Unaffected</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>
            <label>
              Minimum CVSS
              <input
                type="number"
                min="0"
                max="10"
                step="0.1"
                value={draft.cvss_min}
                onChange={(e) => setDraft({ ...draft, cvss_min: e.target.value })}
              />
            </label>
            <label>
              Maximum CVSS
              <input
                type="number"
                min="0"
                max="10"
                step="0.1"
                value={draft.cvss_max}
                onChange={(e) => setDraft({ ...draft, cvss_max: e.target.value })}
              />
            </label>
            <label>
              Updated from
              <input
                type="date"
                value={draft.updated_from}
                onChange={(e) => setDraft({ ...draft, updated_from: e.target.value })}
              />
            </label>
            <label>
              Updated through
              <input
                type="date"
                value={draft.updated_to}
                onChange={(e) => setDraft({ ...draft, updated_to: e.target.value })}
              />
            </label>
          </div>
        </details>
        <button type="submit">Search</button>
        <button type="button" onClick={handleReset}>
          Reset
        </button>
      </form>

      <div className="layout">
        <section className="results">
          {view === "ncsc" ? (
            <NcscAdvisories onSelectCve={handleSelect} />
          ) : (
            <>
              {results && <CveTable items={results.items} onSelect={handleSelect} />}
              {results && (
                <div className="pager">
                  <span className="muted">
                    {firstRow}-{lastRow}{results.has_more ? "+" : ""}
                  </span>
                  <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                    Previous
                  </button>
                  <button type="button" disabled={!results.has_more} onClick={() => setOffset(offset + PAGE_SIZE)}>
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </section>

        <aside>
          {selected ? (
            <CveDetail record={selected} onClose={() => setSelected(null)} />
          ) : (
            <p className="muted">Select a CVE to see its details.</p>
          )}
        </aside>
      </div>
    </div>
  );
}

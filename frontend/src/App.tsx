import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { fetchCve, fetchCves, fetchStats } from "./api";
import { CveDetail } from "./components/CveDetail";
import { CveTable } from "./components/CveTable";
import { StatsBar } from "./components/StatsBar";
import type { CveFilters, CveRecord, ListResponse, StatsResponse } from "./types";

const PAGE_SIZE = 50;
const EMPTY_FILTERS: CveFilters = { q: "", cve_id: "", state: "", severity: "" };
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function App() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [draft, setDraft] = useState<CveFilters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<CveFilters>(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);
  const [results, setResults] = useState<ListResponse | null>(null);
  const [selected, setSelected] = useState<CveRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchStats().then(setStats).catch((e: Error) => setError(e.message));
  }, []);

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

  const total = results?.total ?? 0;
  const firstRow = total === 0 ? 0 : offset + 1;
  const lastRow = Math.min(offset + PAGE_SIZE, total);

  return (
    <div className="app">
      <header>
        <h1>ITL CVE Explorer</h1>
        <span className="muted">CVE List V5 import</span>
      </header>

      {error && <div className="error">{error}</div>}
      {stats && <StatsBar stats={stats} onSelect={handleSelect} />}

      <form className="filters" onSubmit={handleSearch}>
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
        <button type="submit">Search</button>
        <button type="button" onClick={handleReset}>
          Reset
        </button>
      </form>

      <div className="layout">
        <section className="results">
          {results && <CveTable items={results.items} onSelect={handleSelect} />}
          {results && (
            <div className="pager">
              <span className="muted">
                {firstRow}-{lastRow} of {total.toLocaleString()}
              </span>
              <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                Previous
              </button>
              <button type="button" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                Next
              </button>
            </div>
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

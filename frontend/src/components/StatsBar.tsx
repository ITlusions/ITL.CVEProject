import type { StatsResponse } from "../types";
import { formatDate } from "../format";

interface Props {
  stats: StatsResponse;
  onSelect: (cveId: string) => void;
  onSelectCwe: (cweId: string) => void;
}

export function StatsBar({ stats, onSelect, onSelectCwe }: Props) {
  const stateCount = (state: string) => stats.by_state.find((s) => s.state === state)?.count ?? 0;
  const severityCount = (severity: string) =>
    stats.by_severity.find((s) => s.severity === severity)?.count ?? 0;

  return (
    <>
      <section className="stats">
        <div className="card">
          <span>Published</span>
          <strong>{stateCount("PUBLISHED").toLocaleString()}</strong>
        </div>
        <div className="card">
          <span>Rejected</span>
          <strong>{stateCount("REJECTED").toLocaleString()}</strong>
        </div>
        <div className="card">
          <span>Critical (CVSS 3.x)</span>
          <strong>{severityCount("CRITICAL").toLocaleString()}</strong>
        </div>
        <div className="card">
          <span>Last import</span>
          <strong className="small">{formatDate(stats.last_import)}</strong>
        </div>
        <div className="card">
          <span>Last updated</span>
          <strong className="small">{formatDate(stats.latest_update)}</strong>
        </div>
      </section>
      <section className="recent">
        <h2>Recently updated</h2>
        <ul>
          {stats.recent.map((r) => (
            <li key={r.cve_id}>
              <button type="button" className="link" onClick={() => onSelect(r.cve_id)}>
                {r.cve_id}
              </button>
              <span className="muted"> {r.title ?? ""}</span>
            </li>
          ))}
        </ul>
      </section>
      <section className="recent top-cwes">
        <h2>Most common weaknesses</h2>
        {stats.top_weaknesses.length > 0 ? (
          <ol className="top-cwe-list">
            {stats.top_weaknesses.map((weakness) => {
              const maximum = stats.top_weaknesses[0].cve_count;
              const title = weakness.name ?? "Uncatalogued weakness";
              return (
                <li key={weakness.cwe_id}>
                  <button
                    type="button"
                    className="top-cwe"
                    onClick={() => onSelectCwe(weakness.cwe_id)}
                    title={`Filter CVEs for ${weakness.cwe_id}`}
                  >
                    <span className="top-cwe-id">{weakness.cwe_id}</span>
                    <span className="top-cwe-label">
                      <span>{title}</span>
                      <span className="top-cwe-track" aria-hidden="true">
                        <span style={{ width: `${(weakness.cve_count / maximum) * 100}%` }} />
                      </span>
                    </span>
                    <strong>{weakness.cve_count.toLocaleString()}</strong>
                  </button>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="muted">No CWE mappings available.</p>
        )}
      </section>
    </>
  );
}

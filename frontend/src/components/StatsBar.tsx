import type { StatsResponse } from "../types";
import { formatDate } from "../format";

interface Props {
  stats: StatsResponse;
  onSelect: (cveId: string) => void;
}

export function StatsBar({ stats, onSelect }: Props) {
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
    </>
  );
}

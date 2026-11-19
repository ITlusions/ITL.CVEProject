import { useEffect, useRef, useState } from "react";
import { fetchNcscAdvisories, fetchNcscAdvisory } from "../api";
import { formatDate, formatEpss } from "../format";
import type { NcscAdvisoryDetail, NcscListResponse } from "../types";

const PAGE_SIZE = 25;
type Priority = "priority" | "kev" | "all";
const PRIORITY_LABELS: Record<Priority, string> = {
  priority: "KEV or EPSS ≥ 50%",
  kev: "Known exploited (KEV)",
  all: "All advisories",
};

interface Props {
  onSelectCve: (cveId: string) => void;
}

export function NcscAdvisories({ onSelectCve }: Props) {
  const [priority, setPriority] = useState<Priority>("priority");
  const [offset, setOffset] = useState(0);
  const [results, setResults] = useState<NcscListResponse | null>(null);
  const [detail, setDetail] = useState<NcscAdvisoryDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const detailRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchNcscAdvisories(priority, PAGE_SIZE, offset)
      .then((data) => {
        setResults(data);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, [priority, offset]);

  function handlePriorityChange(value: Priority) {
    setPriority(value);
    setOffset(0);
    setDetail(null);
  }

  function handleOpenAdvisory(trackingId: string) {
    fetchNcscAdvisory(trackingId)
      .then((data) => {
        setDetail(data);
        requestAnimationFrame(() => detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
      })
      .catch((e: Error) => setError(e.message));
  }

  const summary = results?.summary;
  const itemCount = results?.items.length ?? 0;

  return (
    <section className="ncsc">
      {error && <div className="error">{error}</div>}

      {summary && (
        <div className="ncsc-summary">
          <span>{summary.advisory_count} advisories</span>
          <span>{summary.cve_count} CVEs</span>
          <span>{summary.kev_count} known exploited</span>
          <span>{summary.priority_count} KEV or EPSS ≥ 50%</span>
        </div>
      )}

      <div className="filters">
        <select value={priority} onChange={(e) => handlePriorityChange(e.target.value as Priority)}>
          {(Object.keys(PRIORITY_LABELS) as Priority[]).map((key) => (
            <option key={key} value={key}>
              {PRIORITY_LABELS[key]}
            </option>
          ))}
        </select>
      </div>

      {detail && (
        <div className="ncsc-detail" ref={detailRef}>
          <h2>
            <a href={detail.link} target="_blank" rel="noreferrer">
              {detail.tracking_id}
            </a>
          </h2>
          <p>{detail.title}</p>
          <p className="muted">
            Released {formatDate(detail.current_release_date)} · {detail.cves.length} CVEs
          </p>
          <table className="cve-table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>KEV</th>
                <th>EPSS</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {detail.cves.map((cve) => (
                <tr key={cve.cve_id} onClick={() => onSelectCve(cve.cve_id)} className="clickable">
                  <td>{cve.cve_id}</td>
                  <td>{cve.kev ? "Yes" : "-"}</td>
                  <td>{formatEpss(cve.epss_score)}</td>
                  <td>{cve.state ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {results && (
        <table className="cve-table">
          <thead>
            <tr>
              <th>Advisory</th>
              <th>Title</th>
              <th>Released</th>
              <th>CVEs</th>
              <th>KEV</th>
              <th>Max EPSS</th>
            </tr>
          </thead>
          <tbody>
            {results.items.map((item) => (
              <tr key={item.tracking_id} onClick={() => handleOpenAdvisory(item.tracking_id)} className="clickable">
                <td>{item.tracking_id}</td>
                <td>{item.title ?? "-"}</td>
                <td>{formatDate(item.current_release_date)}</td>
                <td>{item.cve_count}</td>
                <td>{item.kev_count}</td>
                <td>{formatEpss(item.max_epss)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {results && (
        <div className="pager">
          <span className="muted">
            {itemCount === 0 ? 0 : offset + 1}-{offset + itemCount}
            {results.has_more ? "+" : ""}
          </span>
          <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
            Previous
          </button>
          <button type="button" disabled={!results.has_more} onClick={() => setOffset(offset + PAGE_SIZE)}>
            Next
          </button>
        </div>
      )}

    </section>
  );
}

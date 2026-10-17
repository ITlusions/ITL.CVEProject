import type { CveSummary } from "../types";
import { formatDate, formatEpss, severityClass } from "../format";

interface Props {
  items: CveSummary[];
  onSelect: (cveId: string) => void;
}

export function CveTable({ items, onSelect }: Props) {
  if (items.length === 0) {
    return <p className="muted">No matching CVEs.</p>;
  }

  return (
    <table className="cve-table">
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>State</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>KEV</th>
          <th>EPSS</th>
          <th>Updated</th>
          <th>Title</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => (
          <tr key={item.cve_id} className="clickable" onClick={() => onSelect(item.cve_id)}>
            <td>{item.cve_id}</td>
            <td>{item.state}</td>
            <td>
              <span className={severityClass(item.severity)}>{item.severity ?? "-"}</span>
            </td>
            <td>{item.cvss_score ?? "-"}</td>
            <td>{item.kev ? <span className="sev sev-critical">KEV</span> : "-"}</td>
            <td>{formatEpss(item.epss_score)}</td>
            <td>{formatDate(item.date_updated)}</td>
            <td>{item.title ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

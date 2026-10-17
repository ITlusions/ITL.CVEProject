import type { CveRecord } from "../types";
import { formatDate, formatEpss } from "../format";

interface Props {
  record: CveRecord;
  onClose: () => void;
}

export function CveDetail({ record, onClose }: Props) {
  const raw = record.raw as { cveMetadata?: { datePublished?: string } };
  const datePublished = raw.cveMetadata?.datePublished ?? null;

  return (
    <div className="detail">
      <div className="detail-head">
        <h2>{record.cve_id}</h2>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </div>
      <dl>
        <dt>State</dt>
        <dd>{record.state}</dd>
        <dt>Published</dt>
        <dd>{formatDate(datePublished)}</dd>
        <dt>Updated</dt>
        <dd>{formatDate(record.date_updated)}</dd>
        <dt>Imported</dt>
        <dd>{formatDate(record.imported_at)}</dd>
        <dt>Known exploited</dt>
        <dd>{record.kev ? `Yes, added ${formatDate(record.kev_date_added)}` : "No"}</dd>
        {record.kev && (
          <>
            <dt>KEV due date</dt>
            <dd>{formatDate(record.kev_due_date)}</dd>
            <dt>Ransomware use</dt>
            <dd>{record.kev_ransomware ?? "Unknown"}</dd>
          </>
        )}
        <dt>EPSS score</dt>
        <dd>{formatEpss(record.epss_score)}</dd>
        <dt>EPSS percentile</dt>
        <dd>{formatEpss(record.epss_percentile)}</dd>
        <dt>Enriched</dt>
        <dd>{formatDate(record.enriched_at)}</dd>
      </dl>
      {record.title && <h3>{record.title}</h3>}
      <p className="description">{record.description ?? "No description."}</p>
      <details>
        <summary>Raw JSON</summary>
        <pre>{JSON.stringify(record.raw, null, 2)}</pre>
      </details>
    </div>
  );
}

import type { CveRecord } from "../types";
import { formatDate } from "../format";

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

import type { CveRecord } from "../types";
import { formatDate, formatEpss } from "../format";

interface Props {
  record: CveRecord;
  onClose: () => void;
}

export function CveDetail({ record, onClose }: Props) {
  const raw = record.raw as { cveMetadata?: { datePublished?: string } };
  const datePublished = raw.cveMetadata?.datePublished ?? null;
  const weaknesses = record.weaknesses ?? [];

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
      <section className="affected-products" aria-labelledby="affected-products-heading">
        <div className="affected-products-head">
          <h3 id="affected-products-heading">Affected products</h3>
          <span className="muted">{record.affected_products.length}</span>
        </div>
        {record.affected_products.length > 0 ? (
          <ul className="affected-product-list">
            {record.affected_products.map((product, index) => (
              <li className="affected-product" key={`${product.vendor}-${product.product}-${index}`}>
                <strong>{[product.vendor, product.product].filter(Boolean).join(" / ") || "Unknown product"}</strong>
                {product.platforms.length > 0 && <p>Platforms: {product.platforms.join(", ")}</p>}
                {product.versions.length > 0 ? (
                  <ul className="affected-version-list">
                    {product.versions.map((version, versionIndex) => (
                      <li key={`${version.version}-${versionIndex}`}>
                        {version.version && <span>Version: {version.version}</span>}
                        {version.lessThan && <span>Less than: {version.lessThan}</span>}
                        {version.lessThanOrEqual && <span>Less than or equal to: {version.lessThanOrEqual}</span>}
                        {version.status && <span>Status: {version.status}</span>}
                        {version.versionType && <span>Version type: {version.versionType}</span>}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="muted">No version details reported.</p>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">No affected products reported.</p>
        )}
      </section>
      <section className="weaknesses" aria-labelledby="weaknesses-heading">
        <div className="weaknesses-head">
          <h3 id="weaknesses-heading">Weakness classifications</h3>
          <span className="muted">{weaknesses.length}</span>
        </div>
        {weaknesses.length > 0 ? (
          <ul className="weakness-list">
            {weaknesses.map((weakness) => {
              const cweNumber = /^CWE-(\d+)$/i.exec(weakness.cwe_id)?.[1];
              const title = weakness.name ?? weakness.cve_descriptions[0] ?? "Uncatalogued weakness";
              return (
                <li className="weakness-item" key={weakness.cwe_id}>
                  <div className="weakness-title">
                    {cweNumber ? (
                      <a
                        className="cwe-chip"
                        href={`https://cwe.mitre.org/data/definitions/${cweNumber}.html`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {weakness.cwe_id}
                      </a>
                    ) : (
                      <span className="cwe-chip">{weakness.cwe_id}</span>
                    )}
                    <strong>{title}</strong>
                    {weakness.status && <span className="cwe-status">{weakness.status}</span>}
                  </div>
                  {weakness.description && <p className="weakness-description">{weakness.description}</p>}
                  <p className="weakness-source">Source: {weakness.sources.join(", ")}</p>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="muted">No CWE mapping reported.</p>
        )}
      </section>
      <details>
        <summary>Raw JSON</summary>
        <pre>{JSON.stringify(record.raw, null, 2)}</pre>
      </details>
    </div>
  );
}

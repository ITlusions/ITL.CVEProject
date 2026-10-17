export function formatDate(value: string | null | undefined): string {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

export function formatEpss(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  return `${(value * 100).toFixed(2)}%`;
}

export function severityClass(severity: string | null): string {
  return `sev sev-${(severity ?? "none").toLowerCase()}`;
}

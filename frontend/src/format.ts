export function formatDate(value: string | null | undefined): string {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

export function severityClass(severity: string | null): string {
  return `sev sev-${(severity ?? "none").toLowerCase()}`;
}

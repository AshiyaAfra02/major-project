export const num = (n: number) => new Intl.NumberFormat("en-US").format(n);

export const pct = (v: number, digits = 1) => `${(v * 100).toFixed(digits)}%`;

export function timeAgo(value: string | Date): string {
  const t = typeof value === "string" ? new Date(value).getTime() : value.getTime();
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  return new Date(t).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function shortDate(iso: string): string {
  const d = new Date(iso + "T00:00:00Z");
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
}

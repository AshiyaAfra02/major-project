import { Severity } from "@prisma/client";

const RANK: Record<Severity, number> = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/** Converts the ML service's lowercase severity ("high") to the Prisma enum ("HIGH"). */
export function toSeverity(value: string): Severity {
  const up = value.toUpperCase();
  return up in RANK ? (up as Severity) : Severity.NONE;
}

export const severityRank = (s: Severity) => RANK[s];

/** Alert rule: only high-confidence threats (HIGH or CRITICAL) raise an alert. */
export const shouldAlert = (s: Severity) => RANK[s] >= RANK.HIGH;

export const capitalize = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

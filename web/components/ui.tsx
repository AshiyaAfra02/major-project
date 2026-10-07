import clsx from "clsx";
import type { ReactNode } from "react";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {description && (
          <p className="mt-1 max-w-2xl text-sm text-soc-muted">{description}</p>
        )}
      </div>
      {actions && (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      )}
    </div>
  );
}

export function Card({
  title,
  subtitle,
  action,
  className,
  children,
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={clsx("card p-5", className)}>
      {(title || action) && (
        <header className="mb-4 flex items-start justify-between gap-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-white">{title}</h2>}
            {subtitle && (
              <p className="mt-0.5 text-xs text-soc-muted">{subtitle}</p>
            )}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

type Tone = "default" | "good" | "warn" | "bad";

const TONE_TEXT: Record<Tone, string> = {
  default: "text-white",
  good: "text-emerald-400",
  warn: "text-amber-400",
  bad: "text-red-400",
};

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
  icon,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: Tone;
  icon?: ReactNode;
}) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between">
        <span className="label-xs">{label}</span>
        {icon && <span className="text-soc-muted">{icon}</span>}
      </div>
      <div
        className={clsx(
          "mt-3 font-mono text-3xl font-semibold tabular-nums",
          TONE_TEXT[tone],
        )}
      >
        {value}
      </div>
      {hint && <p className="mt-1 text-xs text-soc-muted">{hint}</p>}
    </div>
  );
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "border-red-500/40 bg-red-500/15 text-red-300",
  HIGH: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  MEDIUM: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  LOW: "border-sky-500/40 bg-sky-500/15 text-sky-300",
  NONE: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toUpperCase();

  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
        SEVERITY_STYLE[key] ?? SEVERITY_STYLE.NONE,
      )}
    >
      {key === "NONE" ? "safe" : key}
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  OPEN: "border-red-500/40 text-red-300",
  ACKNOWLEDGED: "border-amber-500/40 text-amber-300",
  RESOLVED: "border-emerald-500/40 text-emerald-300",
};

export function StatusBadge({ status }: { status: string }) {
  const key = status.toUpperCase();

  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        STATUS_STYLE[key] ?? "border-soc-line text-soc-muted",
      )}
    >
      {key.toLowerCase()}
    </span>
  );
}

export function EmptyState({
  title,
  hint,
}: {
  title: string;
  hint?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-soc-line px-6 py-10 text-center">
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="mt-1 text-xs text-soc-muted">{hint}</p>}
    </div>
  );
}

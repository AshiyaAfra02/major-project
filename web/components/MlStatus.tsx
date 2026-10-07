"use client";

import clsx from "clsx";
import { useEffect, useState } from "react";

type State =
  | { kind: "checking" }
  | { kind: "online"; mode: string }
  | { kind: "offline" };

export default function MlStatus() {
  const [state, setState] = useState<State>({ kind: "checking" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "checking" });

    (async () => {
      try {
        const res = await fetch("/api/health", { cache: "no-store" });
        const data = await res.json().catch(() => null);
        if (cancelled) return;

        if (res.ok && data?.ok) {
          setState({ kind: "online", mode: String(data.mode) });
        } else {
          setState({ kind: "offline" });
        }
      } catch {
        if (!cancelled) setState({ kind: "offline" });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const dot =
    state.kind === "checking"
      ? "bg-amber-400 animate-pulse"
      : state.kind === "offline"
        ? "bg-red-500"
        : state.mode === "live"
          ? "bg-emerald-400"
          : "bg-amber-400";

  const text =
    state.kind === "checking"
      ? "Waking ML service..."
      : state.kind === "offline"
        ? "ML service offline"
        : state.mode === "live"
          ? "ML service live"
          : `ML service: ${state.mode} mode`;

  return (
    <div className="rounded-lg border border-soc-line bg-soc-bg/60 px-3 py-2.5">
      <div className="flex items-center gap-2">
        <span className={clsx("h-2 w-2 rounded-full", dot)} />
        <span className="text-xs font-medium text-slate-300">{text}</span>
      </div>

      {state.kind === "offline" && (
        <button
          type="button"
          onClick={() => setAttempt((n) => n + 1)}
          className="mt-1.5 text-[11px] text-emerald-400 hover:underline"
        >
          Retry
        </button>
      )}

      {state.kind === "online" && state.mode !== "live" && (
        <p className="mt-1 text-[11px] text-amber-400/80">
          Some predictions are MOCK.
        </p>
      )}
    </div>
  );
}

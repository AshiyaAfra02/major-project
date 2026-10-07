"use client";

import clsx from "clsx";
import {
  CheckCircle2,
  Link2,
  Loader2,
  MessageSquare,
  ShieldAlert,
} from "lucide-react";
import { useState } from "react";
import { Card, PageHeader, SeverityBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { pct, timeAgo } from "@/lib/format";
import type { ScanResponse } from "@/lib/types";

type Mode = "url" | "text";

const SAMPLES: Record<Mode, { label: string; value: string }[]> = {
  url: [
    {
      label: "Phishing-style URL",
      value:
        "http://paypal-secure-login.verify-account.example.ru/signin.php?id=1",
    },
    {
      label: "Malware-style URL",
      value: "http://192.168.1.1:8080/admin.exe",
    },
    {
      label: "Shortened link",
      value: "http://bit.ly/3xFreeGiftClaim",
    },
    {
      label: "Safe URL",
      value: "https://www.wikipedia.org/wiki/Python",
    },
  ],

  text: [
    {
      label: "Account suspended",
      value:
        "URGENT: your account is suspended. Verify your password now at http://secure-login.example.com",
    },
    {
      label: "Prize scam",
      value:
        "Congratulations! You have won a free gift card. Click here to claim your prize now.",
    },
    {
      label: "Normal message",
      value: "Hey, are we still meeting for lunch tomorrow?",
    },
  ],
};

interface HistoryItem {
  id: string;
  mode: Mode;
  input: string;
  label: string;
  isThreat: boolean;
  severity: string;
  at: string;
}

export default function ScanPage() {
  const [mode, setMode] = useState<Mode>("url");
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  function switchMode(next: Mode) {
    setMode(next);
    setInput("");
    setResult(null);
    setError(null);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();

    const value = input.trim();

    if (!value || loading) return;

    setLoading(true);
    setError(null);

    try {
      const data = await api<ScanResponse>("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          type: mode,
          input: value,
        }),
      });

      setResult(data);

      setHistory((h) =>
        [
          {
            id: data.scan.id,
            mode,
            input: value,
            label: data.prediction.label,
            isThreat: data.prediction.is_threat,
            severity: data.scan.severity,
            at: data.scan.createdAt,
          },
          ...h,
        ].slice(0, 8),
      );
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  const pred = result?.prediction;

  return (
    <>
      <PageHeader
        title="Threat Scanner"
        description="Scan a URL or a message. High-confidence threats automatically raise an alert with a recommended action."
      />

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-3">
          <Card>
            <div className="mb-4 flex gap-2">
              {(
                [
                  ["url", "URL", Link2],
                  ["text", "Message", MessageSquare],
                ] as const
              ).map(([key, label, Icon]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => switchMode(key)}
                  className={clsx(
                    "btn flex-1",
                    mode === key &&
                      "border-emerald-500/60 bg-emerald-500/15 text-emerald-300",
                  )}
                >
                  <Icon size={16} />
                  {label}
                </button>
              ))}
            </div>

            <form onSubmit={submit} className="space-y-3">
              {mode === "url" ? (
                <input
                  className="input font-mono"
                  placeholder="https://example.com/login"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  maxLength={2048}
                  spellCheck={false}
                  autoComplete="off"
                />
              ) : (
                <>
                  <textarea
                    className="input min-h-[140px] resize-y"
                    placeholder="Paste an email, SMS or social-media message..."
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    maxLength={5000}
                  />

                  <p className="text-right text-[11px] text-soc-muted">
                    {input.length} / 5000
                  </p>
                </>
              )}

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading || !input.trim()}
                >
                  {loading && (
                    <Loader2 size={16} className="animate-spin" />
                  )}
                  {loading ? "Scanning..." : "Scan"}
                </button>

                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setInput("");
                    setResult(null);
                    setError(null);
                  }}
                >
                  Clear
                </button>
              </div>

              {loading && (
                <p className="text-xs text-soc-muted">
                  The first request can take up to a minute if the ML service was asleep.
                </p>
              )}
            </form>

            <div className="mt-5 border-t border-soc-line pt-4">
              <p className="label-xs mb-2">Try a sample</p>

              <div className="flex flex-wrap gap-2">
                {SAMPLES[mode].map((s) => (
                  <button
                    key={s.label}
                    type="button"
                    className="btn px-3 py-1.5 text-xs"
                    onClick={() => setInput(s.value)}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          </Card>

          {error && (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}

          {pred && result && (
            <Card>
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  {pred.is_threat ? (
                    <ShieldAlert size={32} className="text-red-400" />
                  ) : (
                    <CheckCircle2
                      size={32}
                      className="text-emerald-400"
                    />
                  )}

                  <div>
                    <p
                      className={clsx(
                        "text-lg font-semibold",
                        pred.is_threat
                          ? "text-red-300"
                          : "text-emerald-300",
                      )}
                    >
                      {pred.is_threat
                        ? `Threat: ${pred.label}`
                        : "Looks safe"}
                    </p>

                    <p className="text-xs text-soc-muted">
                      Confidence {pct(pred.confidence)} · model{" "}
                      {pred.model_version}
                    </p>
                  </div>
                </div>

                <SeverityBadge severity={pred.severity} />
              </div>

              {pred.mock && (
                <p className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
                  MOCK prediction: the model file is not loaded on the ML service, so this result is not real.
                </p>
              )}

              <div className="mt-5">
                <div className="mb-1 flex justify-between text-xs text-soc-muted">
                  <span>Threat score</span>
                  <span className="font-mono">
                    {pct(pred.threat_score)}
                  </span>
                </div>

                <div className="h-2 overflow-hidden rounded-full bg-soc-raised">
                  <div
                    className={clsx(
                      "h-full rounded-full",
                      pred.is_threat
                        ? "bg-red-500"
                        : "bg-emerald-500",
                    )}
                    style={{
                      width: `${Math.max(
                        2,
                        pred.threat_score * 100,
                      )}%`,
                    }}
                  />
                </div>
              </div>

              {pred.reasons.length > 0 && (
                <div className="mt-5">
                  <p className="label-xs mb-2">Why</p>

                  <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
                    {pred.reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              {pred.is_threat && (
                <div className="mt-5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
                  <p className="label-xs mb-1 text-emerald-400">
                    Recommended action
                  </p>
                  <p className="text-sm text-slate-200">
                    {pred.recommended_action}
                  </p>
                </div>
              )}

              <p className="mt-4 text-xs text-soc-muted">
                {result.alert
                  ? "An alert was created. See the Alerts page."
                  : pred.is_threat
                    ? "No alert created (severity below HIGH, or mock result)."
                    : "Scan saved to the dashboard."}
              </p>
            </Card>
          )}
        </div>

        <Card
          title="This session"
          subtitle="Your latest scans"
          className="h-fit lg:col-span-2"
        >
          {history.length === 0 ? (
            <p className="text-sm text-soc-muted">
              Nothing scanned yet.
            </p>
          ) : (
            <ul className="divide-y divide-soc-line">
              {history.map((h) => (
                <li key={h.id} className="py-2.5">
                  <p className="truncate font-mono text-xs text-slate-300">
                    {h.input}
                  </p>

                  <div className="mt-1 flex items-center gap-2 text-xs">
                    <span
                      className={
                        h.isThreat
                          ? "text-red-300"
                          : "text-emerald-300"
                      }
                    >
                      {h.label}
                    </span>

                    <SeverityBadge severity={h.severity} />

                    <span className="ml-auto text-soc-muted">
                      {timeAgo(h.at)}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}

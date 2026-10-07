"use client";

import clsx from "clsx";
import { FileSpreadsheet, Loader2, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, PageHeader, SeverityBadge, StatCard } from "@/components/ui";
import { api } from "@/lib/api";
import { ATTACK_COLORS, AXIS, GRID, TOOLTIP } from "@/lib/chartTheme";
import { num, pct } from "@/lib/format";
import type { NetworkScanResponse } from "@/lib/types";

const MAX_BYTES = 4 * 1024 * 1024;

export default function NetworkPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [res, setRes] = useState<NetworkScanResponse | null>(null);
  const [onlyThreats, setOnlyThreats] = useState(true);

  function pickFile(f: File | undefined | null) {
    setError(null);
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".csv")) return setError("Only .csv files are accepted.");
    if (f.size > MAX_BYTES) return setError("File is larger than 4 MB. Upload fewer rows (max 2000).");
    setFile(f);
  }

  async function analyze(target: File | null) {
    if (!target || loading) return;
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", target);
      const data = await api<NetworkScanResponse>("/api/network", { method: "POST", body: form });
      setRes(data);
    } catch (e) {
      setRes(null);
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  async function runDemo() {
    try {
      const r = await fetch("/demo/demo_network_sample_labeled.csv");
      if (!r.ok) throw new Error("Demo file missing. Copy it into web/public/demo/.");
      const blob = await r.blob();
      const demo = new File([blob], "demo_network_sample_labeled.csv", { type: "text/csv" });
      setFile(demo);
      await analyze(demo);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load the demo file");
    }
  }

  const summary = res?.summary;
  const chartData = summary
    ? Object.entries(summary.label_counts)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
    : [];
  const rows = summary ? summary.results.filter((r) => (onlyThreats ? r.is_threat : true)).slice(0, 200) : [];

  return (
    <>
      <PageHeader
        title="Network Analyzer"
        description="Upload a CSV of network flows. Each row is classified as Normal or one of six attack types."
        actions={
          <>
            <a href="/demo/demo_network_sample.csv" download className="btn">
              <FileSpreadsheet size={16} /> Sample CSV
            </a>
            <button className="btn btn-primary" onClick={runDemo} disabled={loading}>
              Analyze demo file
            </button>
          </>
        }
      />

      <Card className="mb-4">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); pickFile(e.dataTransfer.files?.[0]); }}
          onClick={() => inputRef.current?.click()}
          className={clsx(
            "flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition",
            dragging ? "border-emerald-500 bg-emerald-500/5" : "border-soc-line hover:border-emerald-500/50",
          )}
        >
          <Upload className="mb-2 text-emerald-400" />
          <p className="text-sm font-medium text-slate-200">
            {file ? file.name : "Drop a CSV here or click to browse"}
          </p>
          <p className="mt-1 text-xs text-soc-muted">
            {file ? `${(file.size / 1024).toFixed(0)} KB` : "CICIDS2017-style flow data · max 4 MB · first 2000 rows are analyzed"}
          </p>
          <input ref={inputRef} type="file" accept=".csv,text/csv" className="hidden"
            onChange={(e) => { pickFile(e.target.files?.[0]); e.target.value = ""; }} />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button className="btn btn-primary" disabled={!file || loading} onClick={() => analyze(file)}>
            {loading && <Loader2 size={16} className="animate-spin" />}
            {loading ? "Analyzing..." : "Analyze traffic"}
          </button>
          <p className="text-xs text-soc-muted">
            The deployed model was trained on CICIDS2017. NSL-KDD files are not supported by it.
          </p>
        </div>
        {error && (
          <p className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</p>
        )}
      </Card>

      {summary && res && (
        <>
          {summary.mock && (
            <p className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
              MOCK prediction: the network model file is not loaded, so these results are not real.
            </p>
          )}
          {summary.warnings.filter((w) => !w.startsWith("MOCK")).map((w) => (
            <p key={w} className="mb-2 rounded-lg border border-soc-line bg-soc-raised px-3 py-2 text-xs text-slate-300">{w}</p>
          ))}

          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Flows analyzed" value={num(summary.total_rows)} hint={`model ${summary.model_version}`} />
            <StatCard label="Threats" value={num(summary.threats)} tone={summary.threats ? "bad" : "good"}
              hint={`${pct(summary.threats / Math.max(summary.total_rows, 1))} of flows`} />
            <StatCard label="Attack types" value={Object.keys(summary.recommended_actions).length} tone="warn"
              hint={res.scan.label !== "Normal" ? `dominant: ${res.scan.label}` : "none found"} />
            <StatCard label="Alerts raised" value={res.alerts.length} tone={res.alerts.length ? "warn" : "good"}
              hint={res.evaluation ? `accuracy vs file labels: ${pct(res.evaluation.accuracy)}` : "high/critical only"} />
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card title="Attack-type counts" subtitle="Flows per predicted class">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
                    <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="name" {...AXIS} tickLine={false} />
                    <YAxis allowDecimals={false} {...AXIS} tickLine={false} axisLine={false} />
                    <Tooltip {...TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                    <Bar dataKey="value" name="Flows" radius={[4, 4, 0, 0]}>
                      {chartData.map((d) => (
                        <Cell key={d.name} fill={ATTACK_COLORS[d.name] ?? "#94a3b8"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>

            <Card title="Mitigation" subtitle="Recommended action for each attack type found">
              {Object.keys(summary.recommended_actions).length === 0 ? (
                <p className="text-sm text-emerald-300">No attacks found. Traffic looks normal.</p>
              ) : (
                <ul className="space-y-3">
                  {Object.entries(summary.recommended_actions).map(([label, action]) => {
                    const alert = res.alerts.find((a) => a.attackType === label);
                    return (
                      <li key={label} className="rounded-lg border border-soc-line bg-soc-bg/50 p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-semibold text-white">
                            {label} <span className="font-mono text-xs text-soc-muted">×{summary.label_counts[label]}</span>
                          </span>
                          {alert && <SeverityBadge severity={alert.severity} />}
                        </div>
                        <p className="mt-1 text-xs text-slate-300">{action}</p>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>
          </div>

          <Card
            title="Row-level results"
            subtitle={`Showing up to 200 rows${onlyThreats ? " (threats only)" : ""}`}
            className="mt-4"
            action={
              <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-300">
                <input type="checkbox" checked={onlyThreats} onChange={(e) => setOnlyThreats(e.target.checked)} />
                Threats only
              </label>
            }
          >
            <div className="max-h-96 overflow-auto rounded-lg border border-soc-line">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-soc-raised text-[11px] uppercase tracking-wider text-soc-muted">
                  <tr>
                    <th className="px-3 py-2">Row</th>
                    <th className="px-3 py-2">Prediction</th>
                    <th className="px-3 py-2">Confidence</th>
                    <th className="px-3 py-2">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-line">
                  {rows.map((r) => (
                    <tr key={r.index}>
                      <td className="px-3 py-1.5 font-mono text-xs text-soc-muted">{r.index + 1}</td>
                      <td className="px-3 py-1.5">
                        <span style={{ color: ATTACK_COLORS[r.label] ?? "#e2e8f0" }}>{r.label}</span>
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs">{pct(r.confidence)}</td>
                      <td className="px-3 py-1.5"><SeverityBadge severity={r.severity} /></td>
                    </tr>
                  ))}
                  {rows.length === 0 && (
                    <tr><td colSpan={4} className="px-3 py-6 text-center text-xs text-soc-muted">No rows to show.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </>
  );
}

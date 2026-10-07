"use client";

import { BrainCircuit, CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { useApi } from "@/lib/useApi";
import { Card, PageHeader, SeverityBadge, StatCard } from "@/components/ui";
import { num, pct } from "@/lib/format";

type ModelInfo = {
  name: string;
  version: string;
  loaded: boolean;
  accuracy?: number | null;
  labels?: string[];
  message?: string;
};

type ModelsResponse = {
  models: ModelInfo[];
};

export default function ModelsPage() {
  const { data, error, loading, reload } = useApi<ModelsResponse>("/api/models");
  const models = data?.models ?? [];

  return (
    <>
      <PageHeader
        title="ML Models"
        description="Live status and metadata for the machine-learning models used by CyberShield."
        actions={
          <button className="btn" onClick={reload} disabled={loading}>
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} /> Refresh
          </button>
        }
      />

      {error && (
        <p className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          {error}
        </p>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {models.map((model) => (
          <Card key={`${model.name}-${model.version}`} title={model.name} subtitle={`Version ${model.version}`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {model.loaded ? (
                  <CheckCircle2 className="text-emerald-400" size={18} />
                ) : (
                  <XCircle className="text-red-400" size={18} />
                )}
                <span className={model.loaded ? "text-emerald-300" : "text-red-300"}>
                  {model.loaded ? "Loaded" : "Not loaded"}
                </span>
              </div>
              <BrainCircuit size={20} className="text-soc-muted" />
            </div>

            <div className="mt-5 grid grid-cols-2 gap-3">
              <StatCard
                label="Accuracy"
                value={model.accuracy == null ? "—" : pct(model.accuracy)}
                tone={model.accuracy != null && model.accuracy >= 0.9 ? "good" : "warn"}
              />
              <StatCard
                label="Labels"
                value={num(model.labels?.length ?? 0)}
                hint={model.labels?.join(", ") || "None reported"}
              />
            </div>

            {model.labels?.length ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {model.labels.map((label) => (
                  <SeverityBadge key={label} severity={label} />
                ))}
              </div>
            ) : null}

            {model.message && (
              <p className="mt-4 rounded-lg border border-soc-line bg-soc-bg/50 px-3 py-2 text-xs text-soc-muted">
                {model.message}
              </p>
            )}
          </Card>
        ))}

        {!loading && models.length === 0 && (
          <Card title="No model data">
            <p className="text-sm text-soc-muted">The models API did not return any model records.</p>
          </Card>
        )}
      </div>
    </>
  );
}

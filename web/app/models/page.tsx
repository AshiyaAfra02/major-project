"use client";

import { BrainCircuit, CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { useApi } from "@/lib/useApi";
import { Card, PageHeader, SeverityBadge, StatCard } from "@/components/ui";
import { num, pct } from "@/lib/format";

type ModelInfo = {
  id: string;
  modelKey: string;
  name: string;
  task: string;
  dataset: string;
  isBaseline: boolean;
  served: boolean;
  nTest: number;
  accuracy?: number | null;
  precisionMacro?: number | null;
  recallMacro?: number | null;
  f1Macro?: number | null;
  labels?: string[];
};

type ModelsResponse = {
  models: ModelInfo[];
};

export default function ModelsPage() {
  const { data, error, loading, reload } =
    useApi<ModelsResponse>("/api/models");

  const models = data?.models ?? [];

  return (
    <>
      <PageHeader
        title="ML Models"
        description="Live status and metadata for the machine-learning models used by CyberShield."
        actions={
          <button className="btn" onClick={reload} disabled={loading}>
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
            Refresh
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
          <Card
            key={model.id}
            title={model.name}
            subtitle={`${model.task.toUpperCase()} • ${model.dataset}`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {model.served ? (
                  <CheckCircle2 className="text-emerald-400" size={18} />
                ) : (
                  <XCircle className="text-red-400" size={18} />
                )}

                <span
                  className={
                    model.served
                      ? "text-emerald-300"
                      : "text-red-300"
                  }
                >
                  {model.served ? "Served / Loaded" : "Not served"}
                </span>
              </div>

              <BrainCircuit size={20} className="text-soc-muted" />
            </div>

            <div className="mt-3 text-xs text-soc-muted">
              Model key: <span className="text-soc-text">{model.modelKey}</span>
            </div>

            <div className="mt-5 grid grid-cols-2 gap-3">
              <StatCard
                label="Accuracy"
                value={
                  model.accuracy == null
                    ? "—"
                    : pct(model.accuracy)
                }
                tone={
                  model.accuracy != null && model.accuracy >= 0.9
                    ? "good"
                    : "warn"
                }
              />

              <StatCard
                label="Labels"
                value={num(model.labels?.length ?? 0)}
                hint={model.labels?.join(", ") || "None reported"}
              />
            </div>

            <div className="mt-3 grid grid-cols-2 gap-3">
              <StatCard
                label="F1 Macro"
                value={
                  model.f1Macro == null
                    ? "—"
                    : pct(model.f1Macro)
                }
              />

              <StatCard
                label="Test Samples"
                value={num(model.nTest)}
              />
            </div>

            {model.labels?.length ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {model.labels.map((label) => (
                  <SeverityBadge key={label} severity={label} />
                ))}
              </div>
            ) : null}

            {model.isBaseline && (
              <p className="mt-4 rounded-lg border border-soc-line bg-soc-bg/50 px-3 py-2 text-xs text-soc-muted">
                Baseline model
              </p>
            )}
          </Card>
        ))}

        {!loading && models.length === 0 && (
          <Card title="No model data">
            <p className="text-sm text-soc-muted">
              The models API did not return any model records.
            </p>
          </Card>
        )}
      </div>
    </>
  );
}

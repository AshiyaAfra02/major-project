import { NextRequest, NextResponse } from "next/server";
import { Prisma, ScanType, Severity } from "@prisma/client";
import Papa from "papaparse";
import { prisma } from "@/lib/prisma";
import { predictNetwork } from "@/lib/mlClient";
import { HttpError, handleError } from "@/lib/http";
import { severityRank, shouldAlert, toSeverity } from "@/lib/alerts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

const MAX_BYTES = 4 * 1024 * 1024; // Vercel rejects request bodies over ~4.5 MB
const MAX_ROWS = 2000; // must match MAX_ROWS in ml-service/app/schemas.py

interface Agg {
  count: number;
  maxSeverity: Severity;
  confSum: number;
}

export async function POST(req: NextRequest) {
  try {
    let form: FormData;
    try {
      form = await req.formData();
    } catch {
      throw new HttpError(400, "Expected multipart/form-data with a 'file' field.");
    }

    const file = form.get("file");
    if (!(file instanceof File)) throw new HttpError(400, "Missing 'file' field.");
    if (!file.name.toLowerCase().endsWith(".csv")) throw new HttpError(400, "Only .csv files are accepted.");
    if (file.size === 0) throw new HttpError(400, "The file is empty.");
    if (file.size > MAX_BYTES) {
      throw new HttpError(413, `File is too large (max ${MAX_BYTES / 1024 / 1024} MB). Upload fewer rows.`);
    }

    const parsed = Papa.parse<Record<string, unknown>>(await file.text(), {
      header: true,
      skipEmptyLines: true,
      dynamicTyping: true,
      transformHeader: (h) => h.trim(),
    });
    let rows = parsed.data;
    if (!rows.length) throw new HttpError(400, "The CSV has no data rows.");

    const warnings: string[] = [];
    if (rows.length > MAX_ROWS) {
      rows = rows.slice(0, MAX_ROWS);
      warnings.push(`File has more than ${MAX_ROWS} rows; only the first ${MAX_ROWS} were analyzed.`);
    }

    // If the file has a "label" column (like the labeled demo file), use it to report accuracy.
    const labelKey = (parsed.meta.fields ?? []).find((f) => f.toLowerCase() === "label");
    const truth = labelKey ? rows.map((r) => String(r[labelKey] ?? "").trim()) : null;

    const payload = rows.map((r) => {
      const clean: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(r)) {
        if (k === "__parsed_extra" || k === labelKey) continue;
        clean[k] = v;
      }
      return clean;
    });

    const ml = await predictNetwork(payload);
    warnings.push(...ml.warnings);

    // ---- aggregate per attack type ----
    const perLabel: Record<string, Agg> = {};
    let overall: Severity = Severity.NONE;
    for (const r of ml.results) {
      if (!r.is_threat) continue;
      const sev = toSeverity(r.severity);
      const agg = perLabel[r.label] ?? { count: 0, maxSeverity: Severity.NONE, confSum: 0 };
      agg.count += 1;
      agg.confSum += r.confidence;
      if (severityRank(sev) > severityRank(agg.maxSeverity)) agg.maxSeverity = sev;
      perLabel[r.label] = agg;
      if (severityRank(sev) > severityRank(overall)) overall = sev;
    }

    const attackLabels = Object.keys(perLabel);
    const dominant = attackLabels.sort((a, b) => perLabel[b].count - perLabel[a].count)[0] ?? "Normal";
    const total = ml.total_rows;
    const meanConfidence = ml.results.reduce((s, r) => s + r.confidence, 0) / Math.max(total, 1);
    const confidence = ml.threats > 0 ? perLabel[dominant].confSum / perLabel[dominant].count : meanConfidence;

    const alertRows = attackLabels
      .filter((label) => shouldAlert(perLabel[label].maxSeverity) && !ml.mock)
      .map((label) => ({
        title: `${label} traffic detected (${perLabel[label].count} of ${total} flows)`,
        description: `Found in ${file.name.slice(0, 120)}`,
        attackType: label,
        severity: perLabel[label].maxSeverity,
        recommendedAction: ml.recommended_actions[label] ?? "Investigate the flows and review firewall logs.",
        source: ScanType.NETWORK,
        confidence: perLabel[label].confSum / perLabel[label].count,
      }));

    const scan = await prisma.scan.create({
      data: {
        type: ScanType.NETWORK,
        input: file.name.slice(0, 200),
        label: dominant,
        isThreat: ml.threats > 0,
        confidence,
        threatScore: ml.threats / Math.max(total, 1), // share of flows that are threats
        severity: overall,
        mock: ml.mock,
        modelVersion: ml.model_version,
        details: {
          total_rows: total,
          threats: ml.threats,
          label_counts: ml.label_counts,
          severity_counts: ml.severity_counts,
          warnings,
          file_size: file.size,
        } as Prisma.InputJsonValue,
        ...(alertRows.length ? { alerts: { create: alertRows } } : {}),
      },
      include: { alerts: true },
    });

    let evaluation: { labeled_rows: number; accuracy: number } | null = null;
    if (truth) {
      const hits = ml.results.reduce((n, r, i) => n + (r.label === truth[i] ? 1 : 0), 0);
      evaluation = { labeled_rows: truth.length, accuracy: hits / truth.length };
    }

    return NextResponse.json(
      { scan, alerts: scan.alerts, summary: { ...ml, warnings }, evaluation },
      { status: 201 },
    );
  } catch (e) {
    return handleError(e);
  }
}

import { NextRequest, NextResponse } from "next/server";
import { Prisma, ScanType } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { predictText, predictUrl } from "@/lib/mlClient";
import { scanSchema } from "@/lib/validation";
import { handleError, readJson } from "@/lib/http";
import { capitalize, shouldAlert, toSeverity } from "@/lib/alerts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const body = scanSchema.parse(await readJson(req));
    const pred = body.type === "url" ? await predictUrl(body.input) : await predictText(body.input);

    const type = body.type === "url" ? ScanType.URL : ScanType.TEXT;
    const severity = toSeverity(pred.severity);
    const createAlert = pred.is_threat && !pred.mock && shouldAlert(severity);
    const title =
      body.type === "url" ? `${capitalize(pred.label)} URL detected` : "Phishing message detected";

    const scan = await prisma.scan.create({
      data: {
        type,
        input: body.input.slice(0, 500),
        label: pred.label,
        isThreat: pred.is_threat,
        confidence: pred.confidence,
        threatScore: pred.threat_score,
        severity,
        mock: pred.mock,
        modelVersion: pred.model_version,
        details: {
          reasons: pred.reasons,
          probabilities: pred.probabilities,
          recommended_action: pred.recommended_action,
        } as Prisma.InputJsonValue,
        ...(createAlert
          ? {
              alerts: {
                create: {
                  title,
                  description: body.input.slice(0, 160),
                  attackType: pred.label,
                  severity,
                  recommendedAction: pred.recommended_action,
                  source: type,
                  confidence: pred.confidence,
                },
              },
            }
          : {}),
      },
      include: { alerts: true },
    });

    return NextResponse.json(
      { scan, prediction: pred, alert: scan.alerts[0] ?? null },
      { status: 201 },
    );
  } catch (e) {
    return handleError(e);
  }
}

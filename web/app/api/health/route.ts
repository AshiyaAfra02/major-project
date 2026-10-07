import { NextResponse } from "next/server";
import { mlHealth } from "@/lib/mlClient";
import { handleError } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Wakes a sleeping ML service and reports its state. The Scan page can call this on load. */
export async function GET() {
  try {
    const health = await mlHealth();
    return NextResponse.json({ ok: true, mode: health.mode, models: health.models });
  } catch (e) {
    return handleError(e);
  }
}

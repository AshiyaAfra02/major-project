import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { handleError } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const models = await prisma.modelMetric.findMany({
      orderBy: [{ task: "asc" }, { dataset: "asc" }, { f1Macro: "desc" }],
    });
    return NextResponse.json({ models });
  } catch (e) {
    return handleError(e);
  }
}

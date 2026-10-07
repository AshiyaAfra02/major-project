import { NextRequest, NextResponse } from "next/server";
import { AlertStatus } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { alertPatchSchema, idSchema } from "@/lib/validation";
import { handleError, readJson } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const id = idSchema.parse(params.id);
    const { status } = alertPatchSchema.parse(await readJson(req));

    const alert = await prisma.alert.update({
      where: { id },
      data: { status, resolvedAt: status === AlertStatus.RESOLVED ? new Date() : null },
    });
    return NextResponse.json({ alert });
  } catch (e) {
    return handleError(e);
  }
}

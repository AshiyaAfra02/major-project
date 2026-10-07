import { NextRequest, NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { alertsQuerySchema } from "@/lib/validation";
import { handleError } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const q = alertsQuerySchema.parse(Object.fromEntries(req.nextUrl.searchParams));

    const where: Prisma.AlertWhereInput = {};
    if (q.status) where.status = q.status;
    if (q.severity) where.severity = q.severity;

    const [rows, grouped] = await Promise.all([
      prisma.alert.findMany({
        where,
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: q.limit + 1,
        ...(q.cursor ? { cursor: { id: q.cursor }, skip: 1 } : {}),
      }),
      prisma.alert.groupBy({ by: ["status"], _count: { _all: true } }),
    ]);

    const hasMore = rows.length > q.limit;
    const items = hasMore ? rows.slice(0, q.limit) : rows;
    const counts: Record<string, number> = { OPEN: 0, ACKNOWLEDGED: 0, RESOLVED: 0 };
    for (const g of grouped) counts[g.status] = g._count._all;

    return NextResponse.json({
      items,
      nextCursor: hasMore ? items[items.length - 1].id : null,
      counts,
    });
  } catch (e) {
    return handleError(e);
  }
}

import { NextResponse } from "next/server";
import { AlertStatus, Severity } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { handleError } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DAY = 86_400_000;
const DAYS = 14;
const dayKey = (d: Date) => d.toISOString().slice(0, 10); // UTC day

export async function GET() {
  try {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    const start = new Date(today.getTime() - (DAYS - 1) * DAY);

    const [total, threats, mockScans, openAlerts, criticalOpen, byLabel, byType, recentScans, recentAlerts] =
      await Promise.all([
        prisma.scan.count(),
        prisma.scan.count({ where: { isThreat: true } }),
        prisma.scan.count({ where: { mock: true } }),
        prisma.alert.count({ where: { status: AlertStatus.OPEN } }),
        prisma.alert.count({ where: { status: AlertStatus.OPEN, severity: Severity.CRITICAL } }),
        prisma.scan.groupBy({ by: ["label"], where: { isThreat: true }, _count: { _all: true } }),
        prisma.scan.groupBy({ by: ["type"], _count: { _all: true } }),
        prisma.scan.findMany({
          where: { createdAt: { gte: start } },
          select: { createdAt: true, isThreat: true },
          take: 5000,
        }),
        prisma.alert.findMany({ orderBy: { createdAt: "desc" }, take: 8 }),
      ]);

    const buckets: Record<string, { date: string; scans: number; threats: number }> = {};
    const scansByDay: { date: string; scans: number; threats: number }[] = [];
    for (let i = 0; i < DAYS; i++) {
      const date = dayKey(new Date(start.getTime() + i * DAY));
      const bucket = { date, scans: 0, threats: 0 };
      buckets[date] = bucket;
      scansByDay.push(bucket);
    }
    for (const s of recentScans) {
      const bucket = buckets[dayKey(s.createdAt)];
      if (!bucket) continue;
      bucket.scans += 1;
      if (s.isThreat) bucket.threats += 1;
    }

    const attackTypes = byLabel
      .map((g) => ({ name: g.label, value: g._count._all }))
      .sort((a, b) => b.value - a.value);

    return NextResponse.json({
      kpis: {
        totalScans: total,
        threatsDetected: threats,
        threatRate: total ? threats / total : 0,
        openAlerts,
        criticalOpenAlerts: criticalOpen,
        mockScans,
      },
      scansByDay,
      attackTypes,
      scanTypes: byType.map((g) => ({ type: g.type, count: g._count._all })),
      recentAlerts,
    });
  } catch (e) {
    return handleError(e);
  }
}

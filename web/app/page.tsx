"use client";

import { Activity, BellRing, FlaskConical, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Card,
  EmptyState,
  PageHeader,
  SeverityBadge,
  StatCard,
  StatusBadge,
} from "@/components/ui";
import { AXIS, GRID, PALETTE, TOOLTIP } from "@/lib/chartTheme";
import { num, pct, shortDate, timeAgo } from "@/lib/format";
import type { StatsResponse } from "@/lib/types";
import { useApi } from "@/lib/useApi";

export default function DashboardPage() {
  const { data, error, loading, reload } =
    useApi<StatsResponse>("/api/stats");

  useEffect(() => {
    const id = setInterval(reload, 30_000);
    return () => clearInterval(id);
  }, [reload]);

  if (error && !data) {
    return (
      <>
        <PageHeader title="Security Operations" />
        <Card>
          <EmptyState
            title="Could not load dashboard data"
            hint={error}
          />
          <div className="mt-4 text-center">
            <button className="btn" onClick={reload}>
              Retry
            </button>
          </div>
        </Card>
      </>
    );
  }

  if (!data) {
    return (
      <>
        <PageHeader title="Security Operations" />
        <p className="text-sm text-soc-muted">
          {loading ? "Loading dashboard..." : ""}
        </p>
      </>
    );
  }

  const { kpis, scansByDay, attackTypes, recentAlerts, scanTypes } = data;
  const totalAttacks = attackTypes.reduce((s, a) => s + a.value, 0);

  return (
    <>
      <PageHeader
        title="Security Operations"
        description="Live overview of scans, detected threats and open alerts."
        actions={
          <>
            <Link href="/scan" className="btn btn-primary">
              New scan
            </Link>
            <button className="btn" onClick={reload}>
              Refresh
            </button>
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total scans"
          value={num(kpis.totalScans)}
          icon={<Activity size={18} />}
          hint={
            scanTypes.map((s) => `${s.count} ${s.type.toLowerCase()}`).join(" · ") ||
            "no scans yet"
          }
        />

        <StatCard
          label="Threats detected"
          value={num(kpis.threatsDetected)}
          tone="bad"
          icon={<ShieldAlert size={18} />}
          hint={`${pct(kpis.threatRate)} of all scans`}
        />

        <StatCard
          label="Open alerts"
          value={num(kpis.openAlerts)}
          tone="warn"
          icon={<BellRing size={18} />}
          hint={`${kpis.criticalOpenAlerts} critical`}
        />

        <StatCard
          label="MOCK scans"
          value={num(kpis.mockScans)}
          tone={kpis.mockScans ? "warn" : "good"}
          icon={<FlaskConical size={18} />}
          hint={
            kpis.mockScans
              ? "made while a model file was missing"
              : "all predictions use real models"
          }
        />
      </div>

      {kpis.totalScans === 0 && (
        <div className="mt-6">
          <EmptyState
            title="No data yet"
            hint="Run `npx prisma db seed` in the web folder, or scan something."
          />
        </div>
      )}

      <div className="mt-6 grid gap-4 lg:grid-cols-3">
        <Card
          title="Attacks over time"
          subtitle="Scans and threats per day (last 14 days, UTC)"
          className="lg:col-span-2"
        >
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={scansByDay}
                margin={{ top: 8, right: 8, left: -16, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="gScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>

                <CartesianGrid
                  stroke={GRID}
                  strokeDasharray="3 3"
                  vertical={false}
                />

                <XAxis
                  dataKey="date"
                  tickFormatter={shortDate}
                  {...AXIS}
                  tickLine={false}
                />

                <YAxis
                  allowDecimals={false}
                  {...AXIS}
                  tickLine={false}
                  axisLine={false}
                />

                <Tooltip
                  {...TOOLTIP}
                  labelFormatter={(l) => shortDate(String(l))}
                />

                <Area
                  type="monotone"
                  dataKey="scans"
                  name="Scans"
                  stroke="#38bdf8"
                  fill="url(#gScans)"
                  strokeWidth={2}
                />

                <Area
                  type="monotone"
                  dataKey="threats"
                  name="Threats"
                  stroke="#ef4444"
                  fill="url(#gThreats)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card
          title="Attack types"
          subtitle={`${totalAttacks} threats by category`}
        >
          {attackTypes.length === 0 ? (
            <EmptyState title="No threats yet" />
          ) : (
            <>
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={attackTypes}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={2}
                      stroke="#0b1220"
                    >
                      {attackTypes.map((_, i) => (
                        <Cell
                          key={i}
                          fill={PALETTE[i % PALETTE.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip {...TOOLTIP} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <ul className="mt-2 space-y-1.5">
                {attackTypes.slice(0, 7).map((a, i) => (
                  <li
                    key={a.name}
                    className="flex items-center justify-between text-xs"
                  >
                    <span className="flex items-center gap-2 text-slate-300">
                      <span
                        className="h-2.5 w-2.5 rounded-sm"
                        style={{
                          background:
                            PALETTE[i % PALETTE.length],
                        }}
                      />
                      {a.name}
                    </span>

                    <span className="font-mono text-soc-muted">
                      {a.value}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>
      </div>

      <Card
        title="Recent alerts"
        subtitle="Newest high-confidence threats"
        className="mt-4"
        action={
          <Link
            href="/alerts"
            className="text-xs text-emerald-400 hover:underline"
          >
            View all
          </Link>
        }
      >
        {recentAlerts.length === 0 ? (
          <EmptyState title="No alerts" />
        ) : (
          <ul className="divide-y divide-soc-line">
            {recentAlerts.map((a) => (
              <li
                key={a.id}
                className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-white">
                    {a.title}
                  </p>
                  <p className="truncate text-xs text-soc-muted">
                    {a.description ?? a.attackType}
                  </p>
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <StatusBadge status={a.status} />
                  <span className="w-16 text-right text-xs text-soc-muted">
                    {timeAgo(a.createdAt)}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

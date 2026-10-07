import { Activity, BellRing, ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, PageHeader, SeverityBadge, StatCard } from "@/components/ui";

export default function DashboardPage() {
  return (
    <>
      <PageHeader
        title="Security Operations"
        description="Live overview of scans, detected threats and open alerts. The real dashboard is built in Step 7b."
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total scans"
          value="0"
          hint="placeholder"
          icon={<Activity size={18} />}
        />
        <StatCard
          label="Threats"
          value="0"
          tone="bad"
          hint="placeholder"
          icon={<ShieldAlert size={18} />}
        />
        <StatCard
          label="Open alerts"
          value="0"
          tone="warn"
          hint="placeholder"
          icon={<BellRing size={18} />}
        />
        <StatCard
          label="Threat rate"
          value="0%"
          tone="good"
          hint="placeholder"
          icon={<ShieldCheck size={18} />}
        />
      </div>

      <Card
        title="Theme check"
        subtitle="Severity badges used across the app"
        className="mt-6"
      >
        <div className="flex flex-wrap gap-2">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].map((s) => (
            <SeverityBadge key={s} severity={s} />
          ))}
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button className="btn">Default</button>
          <button className="btn btn-primary">Primary</button>
          <button className="btn btn-danger">Danger</button>
        </div>
      </Card>
    </>
  );
}

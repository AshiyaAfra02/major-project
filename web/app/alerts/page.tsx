import { Card, EmptyState, PageHeader } from "@/components/ui";

export default function AlertsPage() {
  return (
    <>
      <PageHeader
        title="Alerts"
        description="High-confidence threats with recommended mitigation."
      />
      <Card>
        <EmptyState title="Coming in Step 7e" />
      </Card>
    </>
  );
}

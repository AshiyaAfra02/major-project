import { Card, EmptyState, PageHeader } from "@/components/ui";

export default function NetworkPage() {
  return (
    <>
      <PageHeader
        title="Network Analyzer"
        description="Upload flow data and classify each row."
      />
      <Card>
        <EmptyState title="Coming in Step 7d" />
      </Card>
    </>
  );
}

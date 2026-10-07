import { Card, EmptyState, PageHeader } from "@/components/ui";

export default function ScanPage() {
  return (
    <>
      <PageHeader
        title="Threat Scanner"
        description="Scan URLs and messages for phishing and malware."
      />
      <Card>
        <EmptyState title="Coming in Step 7c" />
      </Card>
    </>
  );
}

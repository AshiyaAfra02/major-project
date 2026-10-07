import { Card, EmptyState, PageHeader } from "@/components/ui";

export default function ModelsPage() {
  return (
    <>
      <PageHeader
        title="Models"
        description="Evaluation metrics and the rule-based baseline."
      />
      <Card>
        <EmptyState title="Coming in Step 7f" />
      </Card>
    </>
  );
}

export type Severity = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
export type ScanType = "URL" | "TEXT" | "NETWORK";

export interface AlertItem {
  id: string;
  scanId: string | null;
  title: string;
  description: string | null;
  attackType: string;
  severity: Severity;
  status: AlertStatus;
  recommendedAction: string;
  source: ScanType;
  confidence: number;
  createdAt: string;
  resolvedAt: string | null;
}

export interface ScanItem {
  id: string;
  type: ScanType;
  input: string;
  label: string;
  isThreat: boolean;
  confidence: number;
  threatScore: number;
  severity: Severity;
  mock: boolean;
  modelVersion: string;
  details: Record<string, unknown> | null;
  createdAt: string;
}

export interface MlPrediction {
  label: string;
  is_threat: boolean;
  confidence: number;
  threat_score: number;
  severity: string;
  recommended_action: string;
  probabilities: Record<string, number>;
  reasons: string[];
  mock: boolean;
  model_version: string;
}

export interface StatsResponse {
  kpis: {
    totalScans: number;
    threatsDetected: number;
    threatRate: number;
    openAlerts: number;
    criticalOpenAlerts: number;
    mockScans: number;
  };
  scansByDay: { date: string; scans: number; threats: number }[];
  attackTypes: { name: string; value: number }[];
  scanTypes: { type: ScanType; count: number }[];
  recentAlerts: AlertItem[];
}

export interface AlertsResponse {
  items: AlertItem[];
  nextCursor: string | null;
  counts: Record<AlertStatus, number>;
}

export interface ModelMetricRow {
  id: string;
  modelKey: string;
  name: string;
  task: string;
  dataset: string;
  isBaseline: boolean;
  served: boolean;
  nTest: number;
  accuracy: number;
  precisionMacro: number;
  recallMacro: number;
  f1Macro: number;
  labels: string[];
  confusionMatrix: number[][];
  perClass: Record<string, { precision: number; recall: number; f1: number; support: number }>;
  extra: Record<string, unknown> | null;
}

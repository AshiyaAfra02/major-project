import "server-only";

export type Severity = "none" | "low" | "medium" | "high" | "critical";

export interface MlPrediction {
  label: string;
  is_threat: boolean;
  confidence: number;
  threat_score: number;
  severity: Severity;
  recommended_action: string;
  probabilities: Record<string, number>;
  reasons: string[];
  mock: boolean;
  model_version: string;
}

export interface MlNetworkRow {
  index: number;
  label: string;
  confidence: number;
  threat_score: number;
  is_threat: boolean;
  severity: Severity;
}

export interface MlNetworkResponse {
  total_rows: number;
  threats: number;
  label_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  recommended_actions: Record<string, string>;
  results: MlNetworkRow[];
  warnings: string[];
  mock: boolean;
  model_version: string;
}

export interface MlHealth {
  status: string;
  mode: "live" | "partial" | "mock";
  models: Record<string, { loaded: boolean; mock: boolean; error: string | null }>;
  versions: Record<string, string>;
}

export class MlError extends Error {
  status: number;
  retryable: boolean;
  constructor(message: string, status: number, retryable = false) {
    super(message);
    Object.setPrototypeOf(this, MlError.prototype);
    this.name = "MlError";
    this.status = status;
    this.retryable = retryable;
  }
}

// A sleeping Hugging Face Space can need 30-60 s to wake up. Vercel functions have a time limit,
// so the whole retry loop is capped at 50 s (routes set maxDuration = 60).
const TOTAL_BUDGET_MS = 50_000;
const ATTEMPT_TIMEOUT_MS = 20_000;
const RETRYABLE_STATUS = [502, 503, 504];

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function config() {
  const base = (process.env.ML_SERVICE_URL ?? "").replace(/\/+$/, "");
  const key = process.env.ML_API_KEY ?? "";
  if (!base || !key) {
    throw new MlError("ML_SERVICE_URL or ML_API_KEY is not set in the environment.", 500);
  }
  return { base, key };
}

async function readDetail(res: Response): Promise<string> {
  try {
    const data = await res.json();
    const detail = data?.detail ?? data?.error ?? data;
    return typeof detail === "string" ? detail : JSON.stringify(detail).slice(0, 300);
  } catch {
    return `ML service returned HTTP ${res.status}`;
  }
}

async function request<T>(
  path: string,
  opts: { method: "GET" | "POST"; body?: unknown; auth?: boolean },
): Promise<T> {
  const { base, key } = config();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.auth !== false) headers["X-API-Key"] = key;

  const started = Date.now();
  let attempt = 0;
  let lastError: MlError | null = null;

  while (true) {
    attempt += 1;
    const remaining = TOTAL_BUDGET_MS - (Date.now() - started);
    if (remaining < 1000) break;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(ATTEMPT_TIMEOUT_MS, remaining));
    try {
      const res = await fetch(base + path, {
        method: opts.method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: controller.signal,
        cache: "no-store",
      });
      if (res.ok) return (await res.json()) as T;

      if (RETRYABLE_STATUS.includes(res.status)) {
        lastError = new MlError(`ML service returned ${res.status}`, res.status, true);
      } else {
        throw new MlError(await readDetail(res), res.status, false); // 4xx: do not retry
      }
    } catch (e) {
      if (e instanceof MlError && !e.retryable) throw e;
      if (e instanceof MlError) {
        lastError = e;
      } else if (e instanceof Error && e.name === "AbortError") {
        lastError = new MlError("ML service timed out", 503, true);
      } else if (e instanceof SyntaxError) {
        lastError = new MlError("ML service returned an unexpected response", 503, true);
      } else {
        lastError = new MlError("Cannot reach the ML service", 503, true);
      }
    } finally {
      clearTimeout(timer);
    }

    const delay = Math.min(1500 * 2 ** (attempt - 1), 8000);
    if (Date.now() - started + delay >= TOTAL_BUDGET_MS) break;
    await sleep(delay);
  }
  throw lastError ?? new MlError("ML service unavailable", 503, true);
}

export const predictUrl = (url: string) =>
  request<MlPrediction>("/predict/url", { method: "POST", body: { url } });

export const predictText = (text: string) =>
  request<MlPrediction>("/predict/text", { method: "POST", body: { text } });

export const predictNetwork = (rows: Record<string, unknown>[]) =>
  request<MlNetworkResponse>("/predict/network", { method: "POST", body: { rows } });

export const mlHealth = () => request<MlHealth>("/health", { method: "GET", auth: false });

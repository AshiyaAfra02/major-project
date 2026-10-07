// Run with the Next.js dev server AND the ML service both running:
//   cd web && node scripts/test-routes.mjs
import fs from "node:fs";
import path from "node:path";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const DEMO = path.resolve(process.cwd(), "..", "ml", "data", "processed", "demo_network_sample_labeled.csv");

let passed = 0;
let failed = 0;
function check(name, ok, detail = "") {
  ok ? passed++ : failed++;
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name} ${detail}`);
}

async function call(method, url, body) {
  const init = { method, headers: {} };
  if (body instanceof FormData) init.body = body;
  else if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  try {
    const res = await fetch(BASE + url, init);
    let data = null;
    try { data = await res.json(); } catch {}
    return { status: res.status, data };
  } catch (e) {
    console.error(`Cannot reach ${BASE} (${e.cause?.code ?? e.message}). Is "npm run dev" running?`);
    process.exit(1);
  }
}

console.log("\n== Health (may take a while if the ML service is asleep) ==");
let r = await call("GET", "/api/health");
check("GET /api/health", r.status === 200 && r.data.ok, `mode=${r.data?.mode}`);

console.log("\n== Validation ==");
r = await call("POST", "/api/scan", { type: "url", input: "has spaces" });
check("URL with spaces -> 400", r.status === 400);
r = await call("POST", "/api/scan", { type: "text", input: "   " });
check("blank text -> 400", r.status === 400);
r = await call("POST", "/api/scan", { type: "bogus", input: "x" });
check("unknown type -> 400", r.status === 400);
r = await call("PATCH", "/api/alerts/does-not-exist", { status: "RESOLVED" });
check("PATCH unknown alert -> 404", r.status === 404);

console.log("\n== Scans ==");
r = await call("POST", "/api/scan", { type: "url", input: "http://paypal-secure-login.verify-account.example.ru/signin.php?id=1" });
check("bad URL scanned", r.status === 201 && r.data.prediction.is_threat, `-> ${r.data?.prediction?.label} ${r.data?.prediction?.severity} alert=${!!r.data?.alert}`);
r = await call("POST", "/api/scan", { type: "url", input: "https://www.wikipedia.org/wiki/Python" });
check("safe URL scanned", r.status === 201 && !r.data.prediction.is_threat, `-> ${r.data?.prediction?.label}`);
r = await call("POST", "/api/scan", { type: "text", input: "URGENT: your account is suspended. Verify your password now at http://secure-login.example.com" });
check("phishing text scanned", r.status === 201 && r.data.prediction.is_threat, `-> ${r.data?.prediction?.severity} alert=${!!r.data?.alert}`);

console.log("\n== Network upload ==");
if (!fs.existsSync(DEMO)) {
  console.log("  demo file not found, skipping:", DEMO);
} else {
  const form = new FormData();
  form.append("file", new Blob([fs.readFileSync(DEMO)], { type: "text/csv" }), "demo_network_sample_labeled.csv");
  r = await call("POST", "/api/network", form);
  check("POST /api/network", r.status === 201, `status=${r.status} ${r.data?.error ?? ""}`);
  if (r.status === 201) {
    console.log("  label_counts:", r.data.summary.label_counts);
    console.log("  alerts created:", r.data.alerts.length, "| accuracy:", r.data.evaluation?.accuracy);
    check("alerts created for attack types", r.data.alerts.length > 0 || r.data.summary.mock);
  }
  const bad = new FormData();
  bad.append("file", new Blob(["hello"], { type: "text/plain" }), "notes.txt");
  r = await call("POST", "/api/network", bad);
  check("non-CSV -> 400", r.status === 400);
}

console.log("\n== Alerts, stats, models ==");
r = await call("GET", "/api/alerts?limit=5&status=open");
check("GET /api/alerts", r.status === 200 && Array.isArray(r.data.items), `counts=${JSON.stringify(r.data?.counts)}`);
const first = r.data?.items?.[0];
if (first) {
  r = await call("PATCH", `/api/alerts/${first.id}`, { status: "ACKNOWLEDGED" });
  check("PATCH alert -> ACKNOWLEDGED", r.status === 200 && r.data.alert.status === "ACKNOWLEDGED");
}
r = await call("GET", "/api/stats");
check("GET /api/stats", r.status === 200 && r.data.scansByDay?.length === 14, `kpis=${JSON.stringify(r.data?.kpis)}`);
r = await call("GET", "/api/models");
check("GET /api/models", r.status === 200 && r.data.models.length > 0, `${r.data?.models?.length} models`);

console.log(`\nResult: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

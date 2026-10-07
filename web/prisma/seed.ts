import fs from "node:fs";
import path from "node:path";
import { Prisma, PrismaClient, ScanType, Severity, AlertStatus } from "@prisma/client";

const prisma = new PrismaClient();

function mulberry32(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(42);
const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length)];

function severityFor(score: number, isThreat: boolean): Severity {
  if (!isThreat) return Severity.NONE;
  if (score >= 0.95) return Severity.CRITICAL;
  if (score >= 0.85) return Severity.HIGH;
  if (score >= 0.7) return Severity.MEDIUM;
  return Severity.LOW;
}

const NETWORK_ACTIONS: Record<string, string> = {
  DoS: "Enable rate limiting, block source IPs, and check server resources.",
  DDoS: "Activate DDoS protection, rate-limit upstream, and notify the provider.",
  PortScan: "Block the scanning IP, close unused ports, and review firewall rules.",
  BruteForce: "Lock targeted accounts, block the source IP, enforce MFA, and review logs.",
  WebAttack: "Enable WAF rules, sanitize inputs, and review web server logs.",
  Bot: "Isolate the infected host, block C2 traffic, and run malware cleanup.",
};

const URL_ACTIONS: Record<string, string> = {
  phishing: "Block the domain, warn users not to enter credentials, and report it.",
  malware: "Block the URL and scan machines that visited it.",
  defacement: "Treat the site as compromised and notify its administrator.",
};

const TEXT_ACTION =
  "Do not click links or reply. Report it as phishing, delete it, and warn recipients.";

const BAD_URLS: [string, string][] = [
  ["http://paypal-secure-login.verify-account.example.ru/signin.php?id=1", "phishing"],
  ["http://192.168.4.20:8080/update/invoice.exe", "malware"],
  ["http://bit.ly/3xFreeGiftClaim", "phishing"],
  ["http://amaz0n-account-verify.example.top/login", "phishing"],
  ["http://free-crypto-wallet-bonus.example.xyz/claim.zip", "malware"],
  ["http://shop.example.com.hacked-by-xyz.example.net/index.html", "defacement"],
  ["http://secure-bank-update.example.cc/webscr?cmd=login", "phishing"],
];

const GOOD_URLS = [
  "https://www.wikipedia.org/wiki/Python",
  "https://www.google.com/search?q=cats",
  "https://github.com/anthropics",
  "https://docs.python.org/3/",
  "https://www.bbc.com/news",
];

const BAD_TEXTS = [
  "URGENT: your account is suspended. Verify your password now at http://secure-login.example.com",
  "Congratulations! You have won a free gift card. Click here to claim your prize now.",
  "Your package could not be delivered. Pay the small fee here: http://track-parcel.example.top",
  "Final notice: confirm your bank details within 24 hours to avoid closure.",
];

const GOOD_TEXTS = [
  "Hey, are we still meeting for lunch tomorrow?",
  "Please find the meeting notes attached. Let me know if anything is missing.",
  "Can you review my pull request when you get a chance?",
];

const ATTACKS = ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot"];
const DAY = 24 * 60 * 60 * 1000;

async function seedMetrics() {
  const file = path.resolve(process.cwd(), "..", "ml-service", "models", "metrics.json");

  if (!fs.existsSync(file)) {
    console.warn(`metrics.json not found at ${file}. Skipping ModelMetric.`);
    return;
  }

  const data = JSON.parse(fs.readFileSync(file, "utf-8"));
  let n = 0;

  for (const m of data.models) {
    const row = {
      name: m.name as string,
      task: m.task as string,
      dataset: m.dataset as string,
      isBaseline: Boolean(m.is_baseline),
      served: Boolean(m.served),
      nTest: m.n_test as number,
      accuracy: m.accuracy as number,
      precisionMacro: m.precision_macro as number,
      recallMacro: m.recall_macro as number,
      f1Macro: m.f1_macro as number,
      labels: m.labels as Prisma.InputJsonValue,
      confusionMatrix: m.confusion_matrix as Prisma.InputJsonValue,
      perClass: m.per_class as Prisma.InputJsonValue,
      extra: (m.extra ?? {}) as Prisma.InputJsonValue,
    };

    await prisma.modelMetric.upsert({
      where: { modelKey: m.key },
      create: { modelKey: m.key, ...row },
      update: row,
    });

    n++;
  }

  console.log(`ModelMetric: upserted ${n} models`);
}

async function seedDemoScans() {
  const removed = await prisma.scan.deleteMany({ where: { isDemo: true } });

  if (removed.count) {
    console.log(`Removed ${removed.count} old demo scans (alerts cascade)`);
  }

  const now = Date.now();
  const ops: Prisma.PrismaPromise<unknown>[] = [];
  let alerts = 0;

  for (let i = 0; i < 140; i++) {
    const createdAt = new Date(now - rand() * 14 * DAY);
    const r = rand();

    const type: ScanType =
      r < 0.4 ? ScanType.URL : r < 0.7 ? ScanType.TEXT : ScanType.NETWORK;

    const threat =
      rand() < (type === ScanType.NETWORK ? 0.6 : 0.45);

    const score = threat ? 0.6 + rand() * 0.39 : 0.01 + rand() * 0.2;
    const severity = severityFor(score, threat);
    const confidence = threat ? score : 1 - score;

    let input: string;
    let label: string;
    let action = "";
    let details: Record<string, unknown> = { demo: true };

    if (type === ScanType.URL) {
      if (threat) {
        const [u, l] = pick(BAD_URLS);
        input = u;
        label = l;
        action = URL_ACTIONS[l];
      } else {
        input = pick(GOOD_URLS);
        label = "benign";
      }
    } else if (type === ScanType.TEXT) {
      if (threat) {
        input = pick(BAD_TEXTS);
        label = "phishing";
        action = TEXT_ACTION;
      } else {
        input = pick(GOOD_TEXTS);
        label = "safe";
      }
    } else {
      const total = 200 + Math.floor(rand() * 800);
      input = `capture_${String(i + 1).padStart(3, "0")}.csv`;

      if (threat) {
        label = pick(ATTACKS);
        action = NETWORK_ACTIONS[label];
        const bad = Math.floor(total * (0.1 + rand() * 0.4));

        details = {
          demo: true,
          total_rows: total,
          threats: bad,
          label_counts: { Normal: total - bad, [label]: bad },
        };
      } else {
        label = "Normal";
        details = {
          demo: true,
          total_rows: total,
          threats: 0,
          label_counts: { Normal: total },
        };
      }
    }

    const shouldAlert =
      threat &&
      (severity === Severity.HIGH || severity === Severity.CRITICAL);

    let alertData: Prisma.AlertCreateWithoutScanInput | undefined;

    if (shouldAlert) {
      const s = rand();
      const status =
        s < 0.6
          ? AlertStatus.OPEN
          : s < 0.85
            ? AlertStatus.ACKNOWLEDGED
            : AlertStatus.RESOLVED;

      alertData = {
        title: `${label} detected (${type.toLowerCase()} scan)`,
        description: input.slice(0, 160),
        attackType: label,
        severity,
        status,
        recommendedAction: action,
        source: type,
        confidence,
        createdAt,
        resolvedAt:
          status === AlertStatus.RESOLVED
            ? new Date(createdAt.getTime() + 3600_000)
            : null,
      };

      alerts++;
    }

    ops.push(
      prisma.scan.create({
        data: {
          type,
          input: input.slice(0, 500),
          label,
          isThreat: threat,
          confidence,
          threatScore: score,
          severity,
          mock: false,
          modelVersion: "seed",
          details: details as Prisma.InputJsonValue,
          isDemo: true,
          createdAt,
          ...(alertData ? { alerts: { create: alertData } } : {}),
        },
      }),
    );
  }

  await prisma.$transaction(ops);
  console.log(`Scan: created ${ops.length} demo scans, ${alerts} alerts`);
}

async function main() {
  await seedMetrics();
  await seedDemoScans();

  const [scans, alerts, metrics] = await Promise.all([
    prisma.scan.count(),
    prisma.alert.count(),
    prisma.modelMetric.count(),
  ]);

  console.log(
    `Totals -> scans: ${scans}, alerts: ${alerts}, model metrics: ${metrics}`,
  );
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

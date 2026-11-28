// The error and refusal boxes #4970 converted each carry role="alert".
// A source check per file: rendering ~20 pages (most behind queries,
// routers and permissions) would assert the same attribute through far more
// scaffolding. The scan in form-error-adoption.test.ts then holds the line
// repo-wide with an empty baseline.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

const BOXES: Record<string, string[]> = {
  "components/AptSection.tsx": ["{saveErr}"],
  "components/KubePodsPanel.tsx": ["{error}"],
  "components/LLDPSection.tsx": ["Failed to save: {saveErr}"],
  "components/NTPSection.tsx": ["Failed to save: {saveErr}"],
  "components/ResolverSection.tsx": [
    "Override mode requires at least one DNS server.",
    "Failed to save: {saveErr}",
  ],
  "components/SNMPSection.tsx": [
    "formatApiError(revealMutation.error)",
    "Failed to save: {saveErr}",
  ],
  "components/SyslogSection.tsx": ["Failed to save: {saveErr}"],
  "pages/DashboardPage.tsx": ["{pdfError}", "{e.error_detail}"],
  "pages/ReportsPage.tsx": ["Failed to load this report."],
  "pages/admin/AuditPage.tsx": ["PDF export failed:"],
  "pages/admin/DiagnosticsErrorsPage.tsx": [
    "Failed to load errors.",
    "Failed to load detail.",
  ],
  "pages/appliance/LogsTab.tsx": ["formatApiError(run.error)"],
  "pages/appliance/SetupWizardPage.tsx": ["formatApiError(finish.error)"],
  "pages/dns/DriftView.tsx": [
    "} could not\n",
    "Could not build the drift report:",
  ],
  "pages/network/AsnDetailPage.tsx": [
    "WHOIS refresh failed",
    "RPKI refresh failed",
  ],
  "pages/network/MulticastReachabilityTab.tsx": [
    "Failed to load reachability.",
  ],
  "pages/network/looking-glass/QueryTab.tsx": [
    "{submitted.message}",
    "Query failed.",
  ],
  "pages/nmap/NmapScanForm.tsx": ["{error}"],
};

describe("converted refusal boxes carry role=alert (#4970)", () => {
  for (const [file, needles] of Object.entries(BOXES)) {
    it(file, () => {
      const src = readFileSync(join(SRC, file), "utf8");
      for (const n of needles) {
        const at = src.indexOf(n);
        expect(at, `${file} lost "${n}"`).toBeGreaterThan(-1);
        // Walk back to the closest box opening that holds a className.
        const before = src.slice(Math.max(0, at - 700), at);
        const tags = [...before.matchAll(/<(?:p|div|span|td)\b[^<>]*>/g)];
        const mine = tags
          .map((t) => t[0])
          .filter((t) => /text-(destructive|red-|rose-)/.test(t));
        expect(
          mine.length,
          `${file}: no red box before "${n}"`,
        ).toBeGreaterThan(0);
        expect(mine[mine.length - 1], `${file}: "${n}"`).toContain(
          'role="alert"',
        );
      }
    });
  }
});

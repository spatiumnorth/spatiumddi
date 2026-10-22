/**
 * #2260 — UTC/local boundary bugs: ``datetime-local`` round trips and
 * date-only values. Runs under two zones, one each side of UTC, because the
 * bugs are invisible in UTC (CI's own zone) and flip direction across it.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  formatDateOnly,
  fromLocalInputValue,
  parseDateOnly,
  termDaysLeft,
  toLocalInputValue,
} from "./localTime";

const ORIGINAL_TZ = process.env.TZ;
afterEach(() => {
  if (ORIGINAL_TZ === undefined) delete process.env.TZ;
  else process.env.TZ = ORIGINAL_TZ;
});

const ZONES = ["America/New_York", "Europe/Berlin"] as const;

describe.each(ZONES)("in %s", (tz) => {
  const setTz = () => {
    process.env.TZ = tz;
  };

  it("a MAC block's expires_at survives open -> save unchanged", () => {
    setTz();
    const stored = "2026-10-25T15:00:00.000Z";
    // MacBlocksTab: state seeded from toLocalInputValue, save sends
    // fromLocalInputValue. Saving twice must not drift either.
    const once = fromLocalInputValue(toLocalInputValue(stored));
    const twice = fromLocalInputValue(toLocalInputValue(once));
    expect(once).toBe(stored);
    expect(twice).toBe(stored);
  });

  it("the lease-history Since picker round-trips its instant", () => {
    setTz();
    const since = "2026-10-14T09:30:00.000Z";
    const shown = toLocalInputValue(since);
    // The input shows the local wall clock, not the UTC one.
    expect(shown).toBe(
      new Date(since)
        .toLocaleString("sv-SE", { timeZone: tz })
        .replace(" ", "T")
        .slice(0, 16),
    );
    expect(fromLocalInputValue(shown)).toBe(since);
  });

  it("a date-only term renders its own calendar date", () => {
    setTz();
    const d = parseDateOnly("2026-10-20");
    expect([d.getFullYear(), d.getMonth() + 1, d.getDate()]).toEqual([
      2026, 10, 20,
    ]);
    expect(formatDateOnly("2026-10-20")).toBe(
      new Date(2026, 9, 20).toLocaleDateString(),
    );
  });

  it("a term is not expired on its last day", () => {
    setTz();
    const lateEvening = new Date(2026, 9, 20, 23, 30);
    const earlyMorning = new Date(2026, 9, 20, 0, 5);
    expect(termDaysLeft("2026-10-20", lateEvening)).toBe(0);
    expect(termDaysLeft("2026-10-20", earlyMorning)).toBe(0);
    expect(termDaysLeft("2026-10-20", new Date(2026, 9, 19, 12))).toBe(1);
    expect(termDaysLeft("2026-10-20", new Date(2026, 9, 21, 0, 5))).toBe(-1);
  });
});

it("empty / invalid inputs are handled", () => {
  expect(toLocalInputValue(null)).toBe("");
  expect(toLocalInputValue("garbage")).toBe("");
  expect(fromLocalInputValue("")).toBeNull();
});

// ── Source guard ────────────────────────────────────────────────────────
// Flags the two shapes that caused #2260 so the class cannot come back.
// ALLOWLIST entries are "relative/path:reason"-keyed exceptions.
const SRC = fileURLToPath(new URL("..", import.meta.url));
const ALLOWLIST: Record<string, string> = {
  "lib/localTime.ts":
    "the shared helper itself: slices after shifting by the UTC offset",
  "pages/dhcp/ServerDetailModal.tsx":
    "slices an etag hash for display; no datetime-local input involved",
};

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...sources(p));
    else if (/\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name))
      out.push(p);
  }
  return out;
}

describe("source guard (#2260)", () => {
  const files = sources(SRC).map((p) => ({
    rel: relative(SRC, p).split(sep).join("/"),
    text: readFileSync(p, "utf8"),
  }));

  it("no .slice(0, 16) of a timestamp outside the shared helper", () => {
    const bad = files
      .filter((f) => !(f.rel in ALLOWLIST) && /\.slice\(0,\s*16\)/.test(f.text))
      .map((f) => f.rel);
    expect(bad, "use toLocalInputValue from lib/localTime").toEqual([]);
  });

  it("no new Date() of a date-only literal (parses as UTC midnight)", () => {
    const re = /new Date\(\s*["'`]\d{4}-\d{2}-\d{2}["'`]\s*\)/;
    const bad = files.filter((f) => re.test(f.text)).map((f) => f.rel);
    expect(bad, "use parseDateOnly from lib/localTime").toEqual([]);
  });

  it("no new Date(<term end>) on a date-only column", () => {
    const re =
      /new Date\(\s*(?:\w+\.)?(?:termEnd|term_end_date|decom_date)\s*\)/;
    const bad = files.filter((f) => re.test(f.text)).map((f) => f.rel);
    expect(bad, "use parseDateOnly from lib/localTime").toEqual([]);
  });
});

// Guard for #3821: a dialog draws a refusal through <FormError> (role="alert"),
// never as a plain red <p>/<div>, which a screen reader does not announce.
// A source scan, a heuristic: an element with a destructive/red text class,
// opened right after an error-ish `cond &&`, in a file that holds a dialog.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

// Files with open PRs at the time of the sweep: converting them then would
// conflict. Each is a follow-up; the list may only shrink (the second test
// fails when an entry no longer has a plain box, so it must be removed).
const OPEN_PR_FOLLOW_UP = [
  "components/copilot/CopilotDrawer.tsx",
  "pages/SettingsPage.tsx",
  "pages/admin/AlertsPage.tsx",
  "pages/admin/ChangeRequestsPage.tsx",
  "pages/admin/CustomFieldsPage.tsx",
  "pages/appliance/FleetTab.tsx",
  "pages/dhcp/CreatePoolModal.tsx",
  "pages/dhcp/CreateScopeModal.tsx",
  "pages/dns/DNSPage.tsx",
  "pages/ipam/BulkAllocateModal.tsx",
  "pages/ipam/IPAMPage.tsx",
  "pages/ipam/ImportExportModals.tsx",
  "pages/ipam/MoveBlockModal.tsx",
  "pages/ipam/NATPage.tsx",
  "pages/ipam/SubnetPlannerListPage.tsx",
  "pages/network/DICOMPage.tsx",
  "pages/network/SitesPage.tsx",
  "pages/security/NewDevicesPage.tsx",
  "pages/vlans/VLANsPage.tsx",
].map((p) => p + " (open PR, follow-up)");

const allowed = new Set(OPEN_PR_FOLLOW_UP.map((s) => s.split(" ")[0]));

// Conditions that are not a refusal of a save (stored last-run state, field
// hints, page-level notices).
const NOT_A_REFUSAL =
  /last_|fingerbank|error_message|valueError|hostnameErr|errors\.|validationError|pageError|reauthFailed|latest\.|optionsError|syncError/;

const PLAIN_BOX =
  /\{(?<cond>[^{}\n]*?(?:[eE]rr|[fF]ail|[rR]efus)[^{}\n]*?)\s*&&\s*\(?\s*<(?<tag>p|div)\s+className="(?<cls>[^"]*)"\s*>(?:(?!<\/?(?:p|div|ul|li|button)\b)[\s\S])*?<\/\k<tag>>/g;

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? files(join(dir, e.name))
      : e.name.endsWith(".tsx") && !e.name.includes(".test.")
        ? [join(dir, e.name)]
        : [],
  );
}

export function plainRefusalBoxes(source: string): string[] {
  if (!source.includes("Modal") && !source.includes("fixed inset")) return [];
  const out: string[] = [];
  for (const m of source.matchAll(PLAIN_BOX)) {
    const { cond, cls } = m.groups as { cond: string; cls: string };
    if (NOT_A_REFUSAL.test(cond)) continue;
    if (!/text-(destructive|red-)/.test(cls)) continue;
    if (/\bbg-destructive(?!\/)/.test(cls) || /hover:/.test(cls)) continue;
    if (m[0].includes("role=")) continue;
    out.push(cond.trim());
  }
  return out;
}

const found = new Map<string, string[]>();
for (const f of files(SRC)) {
  const hits = plainRefusalBoxes(readFileSync(f, "utf8"));
  if (hits.length) found.set(relative(SRC, f), hits);
}

describe("dialog refusals are announced (#3821)", () => {
  it("detects a plain red refusal box", () => {
    const src = `function XModal(){ return <Modal>{error && <p className="text-xs text-destructive">{error}</p>}</Modal>; }`;
    expect(plainRefusalBoxes(src)).toEqual(["error"]);
    expect(plainRefusalBoxes(src.replace("<p ", '<p role="alert" '))).toEqual(
      [],
    );
  });

  it("no dialog outside the allowlist draws a plain refusal box", () => {
    const offenders = [...found.keys()].filter((f) => !allowed.has(f)).sort();
    expect(
      offenders,
      "use <FormError> from components/ui/form-error instead of a plain red <p>/<div>",
    ).toEqual([]);
  });

  it("the allowlist only shrinks: every entry still has a plain box", () => {
    const stale = [...allowed].filter((f) => !found.has(f)).sort();
    expect(stale, "converted already: remove from OPEN_PR_FOLLOW_UP").toEqual(
      [],
    );
  });
});

// Guard for #3821: a dialog draws a refusal through <FormError> (role="alert"),
// never as a plain red <p>/<div>, which a screen reader does not announce.
// A source scan, a heuristic: an element with a destructive/red text class,
// opened right after an error-ish `cond &&`, in a file that holds a dialog.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

// Conditions that are not a refusal of a save (stored last-run state, field
// hints, page-level notices).
const NOT_A_REFUSAL =
  /last_|fingerbank|error_message|valueError|hostnameErr|errors\.|validationError|pageError|reauthFailed|latest\.|optionsError|syncError|logoError|cr\.error|status === "error"|run\.error/;

const PLAIN_BOX =
  /\{(?<cond>[^{}\n]*?(?:[eE]rr|[fF]ail|[rR]efus)[^{}\n]*?)\s*&&\s*\(?\s*<(?<tag>[a-z][a-z0-9]*)\s+className="(?<cls>[^"]*)"\s*>(?:(?!<\/?(?:p|div|ul|li|button)\b)[\s\S])*?<\/\k<tag>>/g;

// A ternary form, `m.isError ? (<div key=".." className="..">..</div>) : null`,
// with attributes (key) ahead of className (#4404).
const PLAIN_TERNARY =
  /(?<cond>[\w.]*(?:[eE]rr|[fF]ail|[rR]efus)[\w.]*)\s*\?\s*\(?\s*<(?<tag>[a-z][a-z0-9]*)\s+(?:[a-zA-Z-]+=(?:\{[^}]*\}|"[^"]*")\s+)*?className="(?<cls>[^"]*)"\s*>(?:(?!<\/?(?:p|div|ul|li|button)\b)[\s\S])*?<\/\k<tag>>/g;

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? files(join(dir, e.name))
      : e.name.endsWith(".tsx") && !e.name.includes(".test.")
        ? [join(dir, e.name)]
        : [],
  );
}

export function plainRefusalBoxes(source: string, ternary = false): string[] {
  if (!source.includes("Modal") && !source.includes("fixed inset")) return [];
  const out: string[] = [];
  for (const m of [
    ...source.matchAll(PLAIN_BOX),
    ...(ternary ? source.matchAll(PLAIN_TERNARY) : []),
  ]) {
    const { cond, cls } = m.groups as { cond: string; cls: string };
    if (NOT_A_REFUSAL.test(cond)) continue;
    if (!/text-(destructive|red-|rose-)/.test(cls)) continue;
    if (/\bbg-destructive(?!\/)/.test(cls) || /hover:/.test(cls)) continue;
    if (m[0].includes("role=")) continue;
    out.push(cond.trim());
  }
  return out;
}

// An error component (`function ApplyErrorBanner`) whose box carries no role
// is the same defect one call site removed: `<ApplyErrorBanner error={e} />`
// has no className for the scans above to read (#4745).
const ERROR_COMPONENT =
  /\nfunction\s+(?<name>[A-Z]\w*(?:Error|Banner|Refusal)\w*)\s*\([\s\S]*?\n\}\n/g;

export function plainErrorComponents(source: string): string[] {
  const out: string[] = [];
  for (const m of source.matchAll(ERROR_COMPONENT)) {
    const body = m[0];
    if (!/className="[^"]*text-(destructive|red-|rose-)/.test(body)) continue;
    if (body.includes("role=")) continue;
    out.push((m.groups as { name: string }).name);
  }
  return out;
}

// Sites the #4745 widening (rose text, error components) found and that were
// not fixed with it: per file, how many. A ratchet: it may only shrink. Several
// are page-level banners rather than dialogs and need a look before a role.
const KNOWN_UNANNOUNCED: Record<string, number> = {
  "components/copilot/CopilotDrawer.tsx": 1,
  "pages/LogsPage.tsx": 1,
  "pages/RequestsPage.tsx": 1,
  "pages/admin/ApiTokensPage.tsx": 1,
  "pages/admin/DNSBLPage.tsx": 1,
  "pages/admin/UsersPage.tsx": 1,
  "pages/appliance/CertificatesTab.tsx": 1,
  "pages/appliance/ClusterOverview.tsx": 1,
  "pages/appliance/ClusterUpgradeTab.tsx": 8,
  "pages/appliance/EtcdSnapshotsCard.tsx": 2,
  "pages/appliance/FleetTab.tsx": 16,
  "pages/appliance/NetworkTab.tsx": 1,
  "pages/appliance/PairingTab.tsx": 1,
  "pages/appliance/UpgradeImagesTable.tsx": 1,
  "pages/network/BgpFootprintTab.tsx": 1,
  "pages/network/DeviceDetailView.tsx": 1,
  "pages/pcap/PacketCapturePage.tsx": 2,
  "pages/tools/NetworkToolsPage.tsx": 1,
};

const found = new Map<string, string[]>();
for (const f of files(SRC)) {
  const rel = relative(SRC, f);
  const text = readFileSync(f, "utf8");
  const hits = [
    ...plainRefusalBoxes(text, true),
    ...plainErrorComponents(text),
  ];
  if (hits.length) found.set(rel, hits);
}

describe("dialog refusals are announced (#3821)", () => {
  it("detects a plain red refusal box", () => {
    const src = `function XModal(){ return <Modal>{error && <p className="text-xs text-destructive">{error}</p>}</Modal>; }`;
    expect(plainRefusalBoxes(src)).toEqual(["error"]);
    expect(plainRefusalBoxes(src.replace("<p ", '<p role="alert" '))).toEqual(
      [],
    );
  });

  it("detects a plain red span (#4354)", () => {
    const src = `function XModal(){ return <Modal>{err && <span className="mt-2 block text-destructive">{err}</span>}</Modal>; }`;
    expect(plainRefusalBoxes(src)).toEqual(["err"]);
  });

  it("detects a plain red ternary box with key before className (#4404)", () => {
    const src = `function XModal(){ return <Modal>{rows.map((m) => m.isError ? (<div key="a" className="px-3 text-xs text-destructive">{m.error}</div>) : null)}</Modal>; }`;
    expect(plainRefusalBoxes(src, true)).toEqual(["m.isError"]);
    expect(
      plainRefusalBoxes(src.replace("<div ", '<div role="alert" '), true),
    ).toEqual([]);
  });

  it("detects a red rose box and an error component without a role (#4745)", () => {
    const rose = `function XModal(){ return <Modal>{error && <div className="text-sm text-rose-600">{error}</div>}</Modal>; }`;
    expect(plainRefusalBoxes(rose)).toEqual(["error"]);
    const comp = `\nfunction ApplyErrorBanner({ e }) {\n  return <div className="text-destructive">{e}</div>;\n}\n`;
    expect(plainErrorComponents(comp)).toEqual(["ApplyErrorBanner"]);
    expect(
      plainErrorComponents(comp.replace("<div ", '<div role="alert" ')),
    ).toEqual([]);
  });

  it("no dialog draws a new plain refusal box", () => {
    const counts = Object.fromEntries(
      [...found].map(([f, hits]) => [f, hits.length]).sort(),
    );
    expect(
      counts,
      "use <FormError> from components/ui/form-error (or role=alert) instead of a plain red box; do not add to KNOWN_UNANNOUNCED",
    ).toEqual(KNOWN_UNANNOUNCED);
  });
});

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
  /last_|fingerbank|error_message|valueError|hostnameErr|(?<![\w.])errors\.|validationError|pageError|reauthFailed|latest\.|optionsError|syncError|logoError|cr\.error|status === "error"|run\.error/;

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
  /\nfunction\s+(?<name>[A-Z]\w*(?:Error|Banner|Refusal)\w*|(?:[A-Z]\w*)?Conflict\w*)\s*\([\s\S]*?\n\}\n/g;

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

// A tinted refusal box whose red is on the box (`border-destructive/30
// bg-destructive/10`) and on a heading inside it, so no text class sits on the
// box for the scans above to read: Sync with server's push errors (#4942).
const BOX_OPENING =
  /<(?<tag>div|p|section|aside)\b(?<attrs>[^<>]*?\bclassName="(?<cls>[^"]*)"[^<>]*)>/g;

export function plainTintedBoxes(source: string, rel = ""): string[] {
  if (!source.includes("Modal") && !source.includes("fixed inset")) return [];
  const out: string[] = [];
  for (const m of source.matchAll(BOX_OPENING)) {
    const { attrs, cls } = m.groups as { attrs: string; cls: string };
    if (!/\bborder-destructive\/\d+/.test(cls)) continue;
    if (!/\bbg-destructive\/\d+/.test(cls)) continue;
    if (/role=/.test(attrs)) continue;
    // A static warning that names a failure mode, not a result.
    if (rel === "components/ui/delete-choice-modal.tsx") continue;
    // Only a box that talks about an error: a static warning ("irreversible")
    // is advice, not a result the operator is waiting on.
    const inner = source.slice(m.index, m.index + 400);
    if (!/errors?\b|refus|fail/i.test(inner.slice(m[0].length))) continue;
    const line = source.slice(0, m.index).split("\n").length;
    out.push(`line ${line}`);
  }
  return out;
}

// Boxes that are stored or passive state, shown on page load rather than in
// response to something the operator just did. A role="alert" there would be
// announced on every load (FleetTab and ClusterUpgradeTab render many rows), so
// they are exempt by name, with the reason. Everything else the scan finds must
// carry a role (#4765).
const STANDING_STATE: Record<string, { names: string[]; why: string }> = {
  "pages/RequestsPage.tsx": {
    names: ["r.error"],
    why: "a failed request's stored reason, one per table row",
  },
  "pages/appliance/ClusterOverview.tsx": {
    names: ["probeFailed"],
    why: "the stored CoreDNS probe result, standing cluster health",
  },
  "pages/appliance/EtcdSnapshotsCard.tsx": {
    names: ["failed && !inFlight"],
    why: "the stored outcome of the last restore",
  },
  "pages/appliance/ClusterUpgradeTab.tsx": {
    names: [
      "progress.error",
      "progress.release_failed",
      "runError",
      ".error",
      "bump.error",
      "FailureBanner",
    ],
    why: "stored upgrade-run progress, per node and per run",
  },
  "pages/appliance/FleetTab.tsx": {
    names: ["PortConflictBanner", "RoleSwitchStateBanner"],
    why: "a node's standing port-conflict and role-switch state, per row",
  },
};

const found = new Map<string, string[]>();
const exempted = new Map<string, string[]>();
for (const f of files(SRC)) {
  const rel = relative(SRC, f);
  const text = readFileSync(f, "utf8");
  const all = [
    ...plainRefusalBoxes(text, true),
    ...plainErrorComponents(text),
    ...plainTintedBoxes(text, rel),
  ];
  const skip = STANDING_STATE[rel]?.names ?? [];
  const hits = all.filter((h) => !skip.includes(h));
  if (hits.length) found.set(rel, hits);
  const ex = all.filter((h) => skip.includes(h));
  if (ex.length) exempted.set(rel, ex);
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

  it("detects a response's error list and a conflict list without a role (#4832)", () => {
    const list = `function XModal(){ return <Modal>{result.errors.length > 0 && (<div className="mt-1 text-destructive">{result.errors.join("; ")}</div>)}</Modal>; }`;
    expect(plainRefusalBoxes(list)).toEqual(["result.errors.length > 0"]);
    expect(
      plainRefusalBoxes(list.replace("<div ", '<div role="alert" ')),
    ).toEqual([]);
    const hint = `function XModal(){ return <Modal>{errors.name && <p className="text-destructive">{errors.name}</p>}</Modal>; }`;
    expect(plainRefusalBoxes(hint)).toEqual([]);
    const comp = `\nfunction ConflictList({ c }) {\n  return <div className="text-red-900">{c}</div>;\n}\n`;
    expect(plainErrorComponents(comp)).toEqual(["ConflictList"]);
  });

  it("detects a tinted refusal box without a role (#4942)", () => {
    const box = `function XModal(){ return <Modal><div className="mt-2 rounded-md border border-destructive/30 bg-destructive/10 p-3"><div className="text-destructive">Push errors</div></div></Modal>; }`;
    expect(plainTintedBoxes(box)).toEqual(["line 1"]);
    expect(
      plainTintedBoxes(box.replace("<div ", '<div role="alert" ')),
    ).toEqual([]);
  });

  it("no error or refusal box is drawn without a role", () => {
    expect(
      Object.fromEntries(found),
      "use <FormError> from components/ui/form-error (or role=alert) for a refusal; a stored state needs an entry in STANDING_STATE with a reason",
    ).toEqual({});
  });

  it("every standing-state exemption still matches a box", () => {
    for (const [file, { names }] of Object.entries(STANDING_STATE)) {
      expect(exempted.get(file)?.slice().sort(), file).toEqual(
        names.slice().sort(),
      );
    }
  });
});

// Guard for #4371: a form field's label is tied to its control by the one
// shared labelled <Field> (components/ui/field.tsx). Page-local `Field`
// helpers drew a <label> with no htmlFor, leaving the control unnamed, and
// about 25 forms had grown their own copy. A source scan: no file may define
// its own `Field` component unless it is listed below with the reason.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

// path (under src, "/"-separated) -> why its own Field is not a form label.
const ALLOWED: Record<string, string> = {
  "pages/network/BgpFootprintTab.tsx": "read-only <dt>/<dd> row, no control",
  "pages/tools/NetworkToolsPage.tsx": "read-only <dt>/<dd> row, no control",
  "pages/appliance/CertificatesTab.tsx": "read-only <dt>/<dd> row, no control",
  "pages/ipam/IPDetailModal.tsx": "read-only value display, no control",
  "pages/SettingsPage.tsx": "ties its label with aria-labelledby (useId)",
  "pages/admin/AlertsPage.tsx": "ties its label with htmlFor + useId",
  "pages/dhcp/PXEProfilesPage.tsx": "ties its label with htmlFor + useId",
  "pages/admin/BackupPage.tsx": "wraps its control in the <label>",
  "pages/admin/BackupTargetsSection.tsx": "wraps its control in the <label>",
  "pages/ipam/MoveBlockModal.tsx": "wraps its control in the <label>",
};

const OWN_FIELD =
  /^\s*(?:export\s+)?(?:function\s+Field\b|const\s+Field\s*[=:])/m;

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? files(join(dir, e.name))
      : /\.tsx?$/.test(e.name) && !e.name.includes(".test.")
        ? [join(dir, e.name)]
        : [],
  );
}

export function definesOwnField(source: string): boolean {
  return OWN_FIELD.test(source);
}

describe("form labels use the shared Field (#4371)", () => {
  it("detects a page-local Field", () => {
    expect(definesOwnField("function Field({ label }) {}")).toBe(true);
    expect(definesOwnField("export function Field(p) {}")).toBe(true);
    expect(definesOwnField("const Field = () => null;")).toBe(true);
    expect(definesOwnField("function FieldRow() {}")).toBe(false);
    expect(definesOwnField('import { Field } from "x";')).toBe(false);
  });

  it("no file defines its own Field outside the allowlist", () => {
    const own = files(SRC)
      .map((f) => ({ f, rel: relative(SRC, f).split(sep).join("/") }))
      .filter(
        ({ f, rel }) =>
          rel !== "components/ui/field.tsx" &&
          definesOwnField(readFileSync(f, "utf8")),
      )
      .map(({ rel }) => rel);
    expect(own.filter((r) => !(r in ALLOWED))).toEqual([]);
    // An allowlist entry that no longer defines a Field is stale.
    expect(Object.keys(ALLOWED).filter((r) => !own.includes(r))).toEqual([]);
  });
});

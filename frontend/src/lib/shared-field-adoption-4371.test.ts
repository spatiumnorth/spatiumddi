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
  // Settings rows: a label <div> beside the control, tied to nothing. The
  // same defect as #4371; not yet moved onto the shared Field (follow-up).
  "components/NTPSection.tsx": "settings row, follow-up",
  "components/SNMPSection.tsx": "settings row, follow-up",
  "components/LLDPSection.tsx": "settings row, follow-up",
  "components/SyslogSection.tsx": "settings row, follow-up",
  "components/AptSection.tsx": "settings row, follow-up",
  "components/SSHSection.tsx": "settings row, follow-up",
  "components/ResolverSection.tsx": "settings row, follow-up",
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

  // #4387: a Field wraps a non-single-control body in a role="group", and a
  // select or input inside a shared picker is then unnamed unless the picker
  // takes the label through useFieldControl(). Every picker that draws one
  // must; the two below draw no named control of their own.
  it("pickers that draw a select or text input take the Field's label", () => {
    const EXEMPT: Record<string, string> = {
      "components/ui/swatch-picker.tsx": "colour buttons, no select / input",
      "components/ui/filter-mode-picker.tsx": "radio group, names its own",
      "components/AgentLogScopePicker.tsx": "not placed in a Field",
    };
    const drawsControl = /<select\b|<input\b(?![^>]*type="(?:checkbox|radio)")/;
    const missing = files(join(SRC, "components"))
      .map((f) => ({ f, rel: relative(SRC, f).split(sep).join("/") }))
      .filter(({ rel }) => /picker/i.test(rel) && !(rel in EXEMPT))
      .filter(({ f }) => {
        const src = readFileSync(f, "utf8");
        return drawsControl.test(src) && !src.includes("useFieldControl");
      })
      .map(({ rel }) => rel);
    expect(missing).toEqual([]);
  });
});

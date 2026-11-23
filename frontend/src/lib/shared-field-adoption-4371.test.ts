// Guard for #4371: a form field's label is tied to its control by the one
// shared labelled <Field> (components/ui/field.tsx). Page-local `Field`
// helpers drew a <label> with no htmlFor, leaving the control unnamed, and
// about 25 forms had grown their own copy. A source scan: no file may define
// its own `Field` component unless it is listed below with the reason.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ts from "typescript";
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

const CONTROLS = new Set(["input", "select", "textarea"]);

/** Line numbers of every `<label>` in a TSX source that names no control: it
 *  has no `htmlFor`, wraps no input / select / textarea and no `{children}`
 *  slot, sits in no other label, and the next native control after it has no
 *  `id`, `aria-label` or `aria-labelledby`. */
export function unnamedInlineLabels(source: string): number[] {
  const sf = ts.createSourceFile(
    "x.tsx",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const elements: (ts.JsxElement | ts.JsxSelfClosingElement)[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n)) elements.push(n);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  const open = (n: ts.JsxElement | ts.JsxSelfClosingElement) =>
    ts.isJsxElement(n) ? n.openingElement : n;
  const tag = (n: ts.JsxElement | ts.JsxSelfClosingElement) =>
    open(n).tagName.getText();
  const has = (n: ts.JsxElement | ts.JsxSelfClosingElement, names: string[]) =>
    open(n).attributes.properties.some(
      (p) => ts.isJsxAttribute(p) && names.includes(p.name.getText()),
    );
  const lines: number[] = [];
  for (const el of elements) {
    if (tag(el) !== "label" || !ts.isJsxElement(el) || has(el, ["htmlFor"]))
      continue;
    let wraps = false;
    const scan = (n: ts.Node) => {
      if (
        (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n)) &&
        CONTROLS.has(tag(n))
      )
        wraps = true;
      // `{children}` is the control a wrapper component receives.
      if (
        ts.isJsxExpression(n) &&
        n.expression &&
        n.expression.getText() === "children"
      )
        wraps = true;
      ts.forEachChild(n, scan);
    };
    scan(el);
    if (wraps) continue;
    let inLabel = false;
    for (let a = el.parent; a; a = a.parent)
      if (ts.isJsxElement(a) && tag(a) === "label") inLabel = true;
    if (inLabel) continue;
    const next = elements.find(
      (c) => c.getStart() >= el.end && CONTROLS.has(tag(c)),
    );
    if (!next || has(next, ["id", "aria-label", "aria-labelledby"])) continue;
    lines.push(sf.getLineAndCharacterOfPosition(el.getStart()).line + 1);
  }
  return lines;
}

/** Static `id="..."` strings that cannot be unique at runtime: one written
 *  twice in a file, or inside a `.map` / `.flatMap` callback (every item of
 *  the loop gets the same id). Use `useId()` or a keyed id there. */
export function repeatedStaticIds(source: string): string[] {
  const sf = ts.createSourceFile(
    "x.tsx",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const seen = new Map<string, number>();
  const bad: string[] = [];
  const visit = (n: ts.Node) => {
    if (
      ts.isJsxAttribute(n) &&
      n.name.getText() === "id" &&
      n.initializer &&
      ts.isStringLiteral(n.initializer)
    ) {
      const id = n.initializer.text;
      seen.set(id, (seen.get(id) ?? 0) + 1);
      let inLoop = false;
      for (let a: ts.Node | undefined = n.parent; a; a = a.parent)
        if (
          ts.isCallExpression(a) &&
          /\.(map|flatMap)$/.test(a.expression.getText())
        )
          inLoop = true;
      if (inLoop) bad.push(`${id} (in a loop)`);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  for (const [id, n] of seen) if (n > 1) bad.push(`${id} (x${n})`);
  return bad;
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

  // #4778: an inline <label> is no Field. A label that names nothing (no
  // htmlFor, wrapping no control) over a control with no id, aria-label or
  // aria-labelledby leaves the control announced by its placeholder, or by
  // nothing. The scan walks the JSX of every file.
  it("detects an inline label that names nothing (#4778)", () => {
    const hit = (body: string) =>
      unnamedInlineLabels(`const a = () => (<div>${body}</div>);`).length;
    expect(hit("<label>Name</label><input />")).toBe(1);
    expect(hit('<label htmlFor="x">Name</label><input id="x" />')).toBe(0);
    expect(hit("<label>Name<input /></label>")).toBe(0);
    expect(hit('<label>Name</label><select aria-label="Name" />')).toBe(0);
    expect(hit('<label>Name</label><textarea aria-labelledby="l" />')).toBe(0);
    expect(hit("<label>{children}</label>")).toBe(0);
    expect(hit("<label>Name</label><p>no control</p>")).toBe(0);
  });

  it("no inline label is left naming nothing (#4778)", () => {
    const left = files(SRC)
      .filter((f) => f.endsWith(".tsx"))
      .flatMap((f) =>
        unnamedInlineLabels(readFileSync(f, "utf8")).map(
          (line) => `${relative(SRC, f).split(sep).join("/")}:${line}`,
        ),
      );
    expect(left).toEqual([]);
  }, 60_000);

  it("detects a static id that repeats at runtime (#4778)", () => {
    const bad = (body: string) =>
      repeatedStaticIds(`const a = () => (<div>${body}</div>);`).length;
    expect(bad('<input id="a" /><input id="b" />')).toBe(0);
    expect(bad('<input id="a" /><input id="a" />')).toBe(1);
    expect(bad('{xs.map((x) => <input key={x} id="a" />)}')).toBe(1);
    expect(bad("{xs.map((x) => <input key={x} id={`a-${x}`} />)}")).toBe(0);
  });

  it("no static id is repeated or written inside a loop (#4778)", () => {
    const left = files(SRC)
      .filter((f) => f.endsWith(".tsx"))
      .flatMap((f) =>
        repeatedStaticIds(readFileSync(f, "utf8")).map(
          (id) => `${relative(SRC, f).split(sep).join("/")}: ${id}`,
        ),
      );
    expect(left).toEqual([]);
  }, 60_000);
});

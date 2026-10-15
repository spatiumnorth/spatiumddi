/**
 * Every icon-only <button> has an accessible name (#1950).
 *
 * A button whose only content is an icon (a lucide component or an <svg>)
 * and that carries no `aria-label`, `aria-labelledby` or `title` is announced
 * by a screen reader as just "button". This walks every component source and
 * fails on each one, naming the file and line, so the next icon-only X /
 * trash / chevron added without a name is caught here instead of by an
 * accessibility audit. Buttons with any text or expression child are left
 * alone (their name comes from the content), as are spread-prop buttons.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const NAMING = new Set(["aria-label", "aria-labelledby", "title"]);
const BUTTONS = new Set(["button", "Button", "HeaderButton"]);

function sources(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) sources(p, out);
    else if (e.name.endsWith(".tsx") && !e.name.includes(".test.")) out.push(p);
  }
  return out;
}

function unnamedIconButtons(file: string): string[] {
  const sf = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const found: string[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isJsxElement(n) && BUTTONS.has(n.openingElement.tagName.getText())) {
      const props = n.openingElement.attributes.properties;
      const named = props.some(
        (a) => ts.isJsxSpreadAttribute(a) || NAMING.has(a.name.getText()),
      );
      let text = false;
      let icon = false;
      for (const c of n.children) {
        if (ts.isJsxText(c)) {
          if (c.text.trim()) text = true;
        } else if (ts.isJsxExpression(c)) {
          if (c.expression) text = true;
        } else {
          const tag = ts.isJsxElement(c)
            ? c.openingElement.tagName.getText()
            : (c as ts.JsxSelfClosingElement).tagName.getText();
          if (/^[A-Z]/.test(tag) || tag === "svg") icon = true;
          else text = true;
        }
      }
      if (!named && icon && !text) {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart());
        found.push(`${file.slice(SRC.length + 1)}:${line + 1}`);
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

describe("icon-only buttons", () => {
  it("all carry an aria-label, aria-labelledby or title", () => {
    const offenders = sources(SRC).flatMap(unnamedIconButtons);
    expect(offenders).toEqual([]);
  });
});

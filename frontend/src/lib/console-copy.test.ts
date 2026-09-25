/**
 * Console copy describes what ships (#1161).
 *
 * Notes written while a feature was being built outlive it. Administration →
 * Backup said destinations beyond a local volume would come "once those
 * drivers ship" above an Add target list of ten; AI Providers said three
 * drivers it already had "ship in Phase 2"; Kubernetes said its reconciler
 * had not shipped; a certificate card said activation did nothing that it
 * does. No review reads every sentence on every page each release, so this
 * does: every string literal, template chunk and JSX text node under `src/`
 * is held against phrases a shipped page has no reason to carry.
 *
 * Comments are not copy and never reach this check — they are not AST
 * nodes — so "#117 Phase 1b" in a code comment is fine. A legitimate use
 * (a product procedure with numbered phases) goes in ALLOWED with its
 * reason, never by loosening a pattern.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("..", import.meta.url));

const PHRASES: { re: RegExp; why: string }[] = [
  { re: /\bPhase \d+[a-z]?\b/, why: "a development-phase label" },
  {
    re: /\bonce (?:those|these|the|its|their)\b[^.]{0,80}?\bships?\b/i,
    why: "describes something as not shipped yet",
  },
  {
    re: /\b(?:coming soon|not yet (?:implemented|supported|available))\b/i,
    why: "roadmap language",
  },
];

/**
 * `<file relative to src/>: <exact text>` pairs that are allowed to match.
 * Each needs a reason a reviewer would accept.
 */
const ALLOWED = new Set([
  // The Windows cutover is a four-phase procedure; these are the tooltips
  // naming each tab's phase of it, not development labels.
  "pages/admin/CutoverPage.tsx: Phase 1 — parity",
  "pages/admin/CutoverPage.tsx: Phase 2 — shadow queries",
  "pages/admin/CutoverPage.tsx: Phase 3 — pre-flight + switch",
  "pages/admin/CutoverPage.tsx: Phase 4 — retire Windows",
]);

/** The copy in one source file: string literals, template chunks, JSX text. */
function copyOf(name: string, source: string): string[] {
  const kind = name.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const file = ts.createSourceFile(
    name,
    source,
    ts.ScriptTarget.Latest,
    false,
    kind,
  );
  const out: string[] = [];
  const visit = (node: ts.Node): void => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node) ||
      ts.isJsxText(node)
    ) {
      // A sentence wraps across source lines; the page shows one space.
      const text = node.text.replace(/\s+/g, " ").trim();
      if (text) out.push(text);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return out;
}

function hitsIn(rel: string, texts: string[]): string[] {
  const hits: string[] = [];
  for (const text of texts) {
    if (ALLOWED.has(`${rel}: ${text}`)) continue;
    for (const { re, why } of PHRASES) {
      const m = re.exec(text);
      if (m) hits.push(`${rel}: "${m[0]}" (${why}) in «${text.slice(0, 160)}»`);
    }
  }
  return hits;
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path));
    else if (
      /\.tsx?$/.test(entry.name) &&
      !/\.(test|d)\.tsx?$/.test(entry.name)
    ) {
      out.push(path);
    }
  }
  return out;
}

describe("console copy (#1161)", () => {
  it("describes no shipped feature as future work", () => {
    const hits: string[] = [];
    for (const file of sourceFiles(SRC)) {
      const rel = relative(SRC, file).split(sep).join("/");
      hits.push(...hitsIn(rel, copyOf(file, readFileSync(file, "utf8"))));
    }
    expect(
      hits,
      "Copy that calls a shipped feature unfinished, or carries a " +
        "development-phase label. Say what the product does today (or move " +
        "the roadmap note to the docs); a true exception goes in ALLOWED.",
    ).toEqual([]);
  });

  it("catches the sentences #1161 found, wherever they sit in the source", () => {
    // Negative control: a scanner that silently reads nothing passes the
    // test above, so prove it still sees the defect in each form it took.
    const source = `
      // Phase 1a — a comment is not copy and must not count
      const hint = "Anthropic / Gemini / Azure drivers ship in Phase 2.";
      const tpl = \`\${hint} once the reconciler ships\`;
      export const Note = () => (
        <p>
          Operators add S3 / SCP / Azure destinations once those
          drivers ship.
        </p>
      );
    `;
    const hits = hitsIn("sample.tsx", copyOf("sample.tsx", source));
    expect(hits.join("\n")).toContain('"Phase 2"');
    expect(hits.join("\n")).toContain("once the reconciler ships");
    expect(hits.join("\n")).toContain("once those drivers ship");
    expect(hits.join("\n")).not.toContain("Phase 1a");
  });
});

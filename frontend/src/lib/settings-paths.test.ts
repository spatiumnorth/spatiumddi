/**
 * Every place in Settings the console's copy sends an operator to exists
 * (#1395).
 *
 * Copy told operators to turn things on under "Settings → …" places the
 * Settings page does not have: "Settings → Features" (the page is Features &
 * Integrations, beside Settings, not in it), "Settings → AI → Tool Catalog"
 * (the AI group holds only Operator Daily Digest), "Settings → Import",
 * "Settings → Backup", and raw column names such as
 * "Settings → acme_enabled". This reads the Settings page's own sidebar —
 * its groups and the sections in each, from `SECTIONS` in
 * `pages/SettingsPage.tsx` — and every "Settings → …" path in the console's
 * copy (string literals, template chunks, JSX text; comments are not copy),
 * and fails on a path whose first step is neither a group nor a section, or
 * whose second step is not a section of that group. Exactly the rule the
 * console's own copy has to keep for an operator to find the place.
 *
 * The backend's copy (module and tool descriptions, the Copilot's words)
 * is held by `backend/tests/test_settings_paths_1395.py`.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("..", import.meta.url));

/** Another product's Settings, named where its own steps are walked. (A
 *  Settings step inside another path — "System → Settings → LLDP" — is
 *  recognised by `INSIDE_ANOTHER_PATH` and needs no entry here.) */
const ALLOWED = new Set([
  // UniFi OS's own console, where the API key is generated.
  "pages/unifi/UnifiPage.tsx: Settings → Control Plane → Integrations",
]);

const PATH = /Settings\s*(?:→|->)\s*([^\n.,;:()"“”]+)/g;
/** "System → Settings → LLDP", "NetBird dashboard → Settings → Users": a
 *  Settings step inside another product's path. */
const INSIDE_ANOTHER_PATH = /(?:→|->)\s*(?:\w+\s+)?$/;

function parse(name: string, source: string): ts.SourceFile {
  const kind = name.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  return ts.createSourceFile(name, source, ts.ScriptTarget.Latest, false, kind);
}

/** The copy in one source file: string literals, template chunks, JSX text. */
function copyOf(name: string, source: string): string[] {
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
      const text = node.text.replace(/\s+/g, " ").trim();
      if (text) out.push(text);
    }
    ts.forEachChild(node, visit);
  };
  visit(parse(name, source));
  return out;
}

/** Settings' sidebar: each group's sections, from `SECTIONS`' object literals. */
function settingsSidebar(): Map<string, string[]> {
  const file = join(SRC, "pages", "SettingsPage.tsx");
  const groups = new Map<string, string[]>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === "SECTIONS" &&
      node.initializer &&
      ts.isArrayLiteralExpression(node.initializer)
    ) {
      for (const el of node.initializer.elements) {
        if (!ts.isObjectLiteralExpression(el)) continue;
        const prop = (key: string) =>
          el.properties
            .filter(ts.isPropertyAssignment)
            .find((p) => ts.isIdentifier(p.name) && p.name.text === key)
            ?.initializer;
        const title = prop("title");
        const group = prop("group");
        if (
          title &&
          group &&
          ts.isStringLiteral(title) &&
          ts.isStringLiteral(group)
        ) {
          groups.set(group.text, [
            ...(groups.get(group.text) ?? []),
            title.text,
          ]);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(parse(file, readFileSync(file, "utf8")));
  return groups;
}

const norm = (s: string) =>
  s.toLowerCase().replace(/&/g, "and").replace(/\s+/g, " ").trim();
/** "IPAM and vendors come back empty" names the IPAM group. */
const begins = (said: string, name: string) =>
  said === name || said.startsWith(`${name} `);

/** ALLOWED entries a scan matched: an entry nothing matches is stale. */
const allowedSeen = new Set<string>();

function deadPaths(
  rel: string,
  texts: string[],
  sidebar: Map<string, string[]>,
): string[] {
  const groups = [...sidebar].map(
    ([g, sections]) => [norm(g), sections.map(norm)] as const,
  );
  const exists = (path: string): boolean => {
    const [first, second] = path.split(/\s*(?:→|->)\s*/).map(norm);
    for (const [g, sections] of groups) {
      if (begins(first, g))
        return !second || sections.some((s) => begins(second, s));
    }
    return groups.some(([, sections]) =>
      sections.some((s) => begins(first, s)),
    );
  };
  const dead: string[] = [];
  for (const text of texts) {
    for (const m of text.matchAll(PATH)) {
      if (INSIDE_ANOTHER_PATH.test(text.slice(0, m.index))) continue;
      const said = `Settings → ${m[1].trim()}`;
      if (ALLOWED.has(`${rel}: ${said}`)) {
        allowedSeen.add(`${rel}: ${said}`);
        continue;
      }
      if (!exists(m[1].trim()))
        dead.push(`${rel}: "${said}" in «${text.slice(0, 160)}»`);
    }
  }
  return dead;
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path));
    else if (
      /\.tsx?$/.test(entry.name) &&
      !/\.(test|d)\.tsx?$/.test(entry.name)
    )
      out.push(path);
  }
  return out;
}

describe("Settings paths in console copy (#1395)", () => {
  const sidebar = settingsSidebar();

  it("reads the Settings sidebar it holds copy against", () => {
    // A scanner that read no sidebar would call every path dead, and one
    // that read the wrong array could call a dead one alive.
    expect([...sidebar.keys()]).toEqual(
      expect.arrayContaining(["Application", "Security", "IPAM", "DNS", "AI"]),
    );
    expect(sidebar.get("AI")).toEqual(["Operator Daily Digest"]);
    expect(sidebar.get("DHCP")).toContain("DHCP Lease Sync");
  });

  it("sends the operator only to Settings places that exist", () => {
    const dead: string[] = [];
    for (const file of sourceFiles(SRC)) {
      const rel = relative(SRC, file).split(sep).join("/");
      const source = readFileSync(file, "utf8");
      if (!/Settings\s*(?:→|->)/.test(source)) continue;
      dead.push(...deadPaths(rel, copyOf(file, source), sidebar));
    }
    expect(
      dead,
      "Copy that sends the operator to a Settings place the Settings page " +
        "does not have. Name the place where the control really is " +
        "(Features & Integrations, Administration → …, Appliance → …); a " +
        "path inside another product's console goes in ALLOWED.",
    ).toEqual([]);
    expect(
      [...ALLOWED].filter((a) => !allowedSeen.has(a)),
      "ALLOWED entries no copy carries any more: remove them",
    ).toEqual([]);
  });

  it("catches the paths #1395 found, and passes real ones", () => {
    // Negative control: the scanner must still see each dead shape.
    const sample = [
      "enable it in Settings → AI → Tool Catalog.",
      "Enable it under Settings → Features first.",
      "explicit operator opt-in (Settings → acme_enabled).",
      "Configure a backup destination at Settings → Backup, run a backup",
      "Open your NetBird dashboard → Settings → Users",
      "OUI lookup is disabled in Settings → IPAM and vendors come back empty.",
      "Enable it under Settings → IPAM → OUI Vendor Lookup.",
    ];
    const dead = deadPaths("sample.tsx", sample, sidebar).join("\n");
    expect(dead).toContain('"Settings → AI → Tool Catalog"');
    expect(dead).toContain('"Settings → Features first"');
    expect(dead).toContain('"Settings → acme_enabled"');
    expect(dead).toContain('"Settings → Backup"');
    expect(dead).not.toContain("NetBird");
    expect(dead).not.toContain("IPAM");
  });
});

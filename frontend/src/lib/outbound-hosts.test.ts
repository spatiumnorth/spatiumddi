/**
 * Every hostname the Web UI names is documented in docs/PRIVACY.md (#1353).
 *
 * The backend half of this guard (`backend/tests/test_outbound_hosts_documented.py`)
 * scanned `backend/app` and the agents, never the frontend. Meanwhile the MFA
 * enrolment screen built its QR code as an `<img>` from api.qrserver.com, with
 * the `otpauth://` URI — TOTP secret included — in the query string: every
 * user enrolling a second factor handed it to a third party. The CSP added in
 * #400 blocked the request from 2026.06.13-1 on (leaving a broken image), but
 * nothing ever noticed the URL, because nothing looked.
 *
 * Telling a URL the browser loads by itself from a link an operator clicks
 * cannot be done by syntax: that QR URL was built into a variable and handed
 * to `src` later. So, like the backend guard, every hostname in the UI's copy
 * and values must appear on the page: in its connection tables, or in its
 * appendix of hosts that are named but never contacted. Classifying one is a
 * sentence a human writes into the document readers actually read.
 *
 * Comments are not scanned (they are not AST nodes); string literals, template
 * chunks, JSX text and attribute values are, plus `index.html`.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("..", import.meta.url));
const FRONTEND = fileURLToPath(new URL("../..", import.meta.url));
const PRIVACY = fileURLToPath(
  new URL("../../../docs/PRIVACY.md", import.meta.url),
);

// No ``{`` or ``$`` in the class, so an interpolated ``https://${host}/`` yields
// no match rather than a fragment.
const URL_RE = /https?:\/\/([A-Za-z0-9._-]+)/g;
// Only something that looks like a real hostname must be documented; this
// drops ``https://localhost``, ``https://...`` and loopback literals.
const HOSTNAME_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...sourceFiles(path));
    } else if (
      /\.tsx?$/.test(entry.name) &&
      !/\.test\.tsx?$/.test(entry.name)
    ) {
      out.push(path);
    }
  }
  return out;
}

/** The text of every string literal, template chunk and JSX text node. */
function stringsOf(name: string, source: string): string[] {
  const kind = name.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const file = ts.createSourceFile(
    name,
    source,
    ts.ScriptTarget.Latest,
    false,
    kind,
  );
  const out: string[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      out.push(node.text);
    } else if (ts.isJsxText(node)) {
      out.push(node.getText(file));
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return out;
}

function hostsIn(text: string): string[] {
  const hosts: string[] = [];
  for (const m of text.matchAll(URL_RE)) {
    const host = m[1].toLowerCase().replace(/\.+$/, "");
    if (HOSTNAME_RE.test(host)) hosts.push(host);
  }
  return hosts;
}

/** The host written on the page as itself, not inside a longer name. */
function documented(host: string, privacy: string): boolean {
  const escaped = host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![\\w.:-])${escaped}(?![\\w:-]|\\.\\w)`).test(privacy);
}

function hostsInUi(): Map<string, Set<string>> {
  const found = new Map<string, Set<string>>();
  const add = (host: string, where: string) => {
    if (!found.has(host)) found.set(host, new Set());
    found.get(host)!.add(where);
  };
  for (const path of sourceFiles(SRC)) {
    const where = relative(SRC, path).split(sep).join("/");
    for (const text of stringsOf(path, readFileSync(path, "utf-8"))) {
      for (const host of hostsIn(text)) add(host, where);
    }
  }
  for (const host of hostsIn(
    readFileSync(join(FRONTEND, "index.html"), "utf-8"),
  )) {
    add(host, "index.html");
  }
  return found;
}

describe("outbound hosts in the Web UI (#1353)", () => {
  it("documents every hostname the UI names in docs/PRIVACY.md", () => {
    const privacy = readFileSync(PRIVACY, "utf-8");
    const missing = [...hostsInUi()]
      .filter(([host]) => !documented(host, privacy))
      .map(([host, files]) => `${host} (${[...files].sort().join(", ")})`)
      .sort();
    expect(
      missing,
      "Each host must be a row in PRIVACY.md §3 (a real connection) or be listed " +
        "in its appendix (named, never contacted).",
    ).toEqual([]);
  });

  it("never names a host PRIVACY.md mentions only as history", () => {
    // PRIVACY.md names api.qrserver.com to explain what leaked, which would
    // also let the test above accept it. These must never come back at all.
    const retired = ["api.qrserver.com"];
    expect([...hostsInUi().keys()].filter((h) => retired.includes(h))).toEqual(
      [],
    );
  });

  it("finds a host built into a variable, the shape that hid the MFA QR", () => {
    const strings = stringsOf(
      "probe.tsx",
      "const qrSrc = `https://api.qrserver.com/v1/create-qr-code/?data=${x}`;",
    );
    expect(strings.flatMap(hostsIn)).toEqual(["api.qrserver.com"]);
  });

  it("does not take a host inside a longer name as documented", () => {
    expect(documented("example.com", "see app.example.com.")).toBe(false);
    expect(documented("app.example.com", "see `app.example.com`.")).toBe(true);
  });
});

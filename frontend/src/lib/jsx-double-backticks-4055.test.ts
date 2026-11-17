// #4055: ``double backticks`` are reStructuredText/docstring style. In JSX text
// they reach the page as typed, so visible copy must use <code> instead.
// Comments may keep them; everything else in a .tsx file may not.
import { describe, expect, it } from "vitest";

const sources = import.meta.glob("/src/**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

function stripComments(src: string): string {
  return src
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

describe("no ``double backticks`` in visible JSX text (#4055)", () => {
  it("finds none outside comments", () => {
    const offenders: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (path.endsWith(".test.tsx")) continue;
      stripComments(src)
        .split("\n")
        .forEach((line, i) => {
          if (line.includes("``"))
            offenders.push(`${path}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(offenders).toEqual([]);
  });
});

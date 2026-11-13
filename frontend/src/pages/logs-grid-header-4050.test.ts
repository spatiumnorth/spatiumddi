// #4050: a grid header whose first cell is an `sr-only` element shifts every
// following header one column left. `sr-only` is `position: absolute`, which
// takes the element out of the CSS grid, while each row still fills that
// track. The screen-reader label has to sit INSIDE a real grid cell.
import { describe, expect, it } from "vitest";

import logsPage from "./LogsPage.tsx?raw";

/** Direct children of each `grid gap-x-3 …` header block in LogsPage. */
function headerBlocks(source: string): string[][] {
  const lines = source.split("\n");
  const blocks: string[][] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes('"grid gap-x-3 border-b')) continue;
    // The opening <div …> closes on a line that is just ">" (prettier style).
    let j = i;
    while (j < lines.length && lines[j].trim() !== ">") j++;
    const childIndent = lines[j].match(/^(\s*)/)![1].length + 2;
    const children: string[] = [];
    for (j += 1; j < lines.length; j++) {
      const line = lines[j];
      const indent = line.match(/^(\s*)/)![1].length;
      if (line.trim() === "</div>" && indent < childIndent) break;
      if (indent === childIndent) children.push(line.trim());
    }
    blocks.push(children);
  }
  return blocks;
}

describe("Logs grid headers (#4050)", () => {
  const blocks = headerBlocks(logsPage);

  it("finds the DNS Queries and DHCP Activity headers", () => {
    expect(blocks.length).toBeGreaterThanOrEqual(2);
  });

  it("never makes an sr-only element a grid cell of its own", () => {
    for (const children of blocks) {
      const bare = children.filter((c) =>
        c.startsWith('<span className="sr-only"'),
      );
      expect(bare).toEqual([]);
    }
  });
});

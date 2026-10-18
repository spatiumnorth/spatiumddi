import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  TEMPLATE_START_MAX,
  expandTemplate,
  hostLabelError,
  storedHostname,
  templateFormatError,
  templateStartError,
} from "./bulk-allocate-template";

// The same file backend/tests/test_ipam_bulk_allocate_template_vectors_2071.py
// reads, so the dialog's live preview and the server's stored names are
// pinned to one set of cases (#2071).
interface Vectors {
  vectors: { template: string; ip: string; n: number; stored: string | null }[];
  template_start: { max: number; accepted: number[]; refused: number[] };
}
const VECTORS = JSON.parse(
  readFileSync(
    new URL("./bulk-allocate-template.vectors.json", import.meta.url),
    "utf8",
  ),
) as Vectors;

/** The dialog's sequence, mirroring the endpoint's. */
function stored(template: string, ip: string, n: number): string | null {
  if (templateFormatError(template) !== null) return null;
  const rendered = expandTemplate(template, ip, n, ip.includes(":"));
  return hostLabelError(rendered) === null ? storedHostname(rendered) : null;
}

describe("bulk allocate template (#2071)", () => {
  it.each(VECTORS.vectors)(
    "$template @ $ip n=$n -> $stored",
    ({ template, ip, n, stored: want }) => {
      expect(stored(template, ip, n)).toBe(want);
    },
  );

  it("enforces the server's iterator bounds", () => {
    const b = VECTORS.template_start;
    expect(TEMPLATE_START_MAX).toBe(b.max);
    for (const n of b.accepted) expect(templateStartError(n)).toBeNull();
    for (const n of b.refused) expect(templateStartError(n)).not.toBeNull();
  });

  it("says why a template is refused", () => {
    expect(templateFormatError("web{n:_}")).toMatch(/not supported/);
    expect(templateFormatError("web{n!r}")).toMatch(/conversions/);
    expect(templateFormatError("web{n")).toMatch(/malformed/);
    expect(hostLabelError("web1-")).toMatch(/web1-/);
    expect(hostLabelError("a".repeat(64))).toMatch(/63/);
  });
});

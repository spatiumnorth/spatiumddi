/** @vitest-environment jsdom */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BreadcrumbPills } from "./IPAMPage";

// #3213 — the block / space / subnet detail headers must wrap rather than
// clip, and long breadcrumb pills must truncate (with a tooltip) rather than
// wrap into tall bubbles.
describe("IPAM detail header wrap (#3213)", () => {
  it("truncates each pill to one line and keeps the full text in a title", () => {
    const long = "10.20.128.0/17 (Laboratory-and-Test-Equipment-Isolated)";
    render(
      <BreadcrumbPills
        items={[
          { label: "Some-Very-Long-Space-Name", variant: "space" },
          { label: long, variant: "block" },
        ]}
      />,
    );
    const pill = screen.getByText(long);
    expect(pill.getAttribute("title")).toBe(long);
    expect(pill.className).toContain("truncate");
    expect(pill.className).toContain("max-w-full");
    expect(pill.parentElement?.parentElement?.className).toContain("flex-wrap");
  });

  it("the three headers wrap and keep their actions unclipped", () => {
    const src = readFileSync(
      resolve(process.cwd(), "src/pages/ipam/IPAMPage.tsx"),
      "utf8",
    );
    expect(
      src.match(/flex-wrap items-center justify-between gap-x-4 gap-y-2/g),
    ).toHaveLength(3);
    expect(src.match(/min-w-\[12rem\] flex-1/g)!.length).toBeGreaterThanOrEqual(
      3,
    );
    expect(
      src.match(/flex max-w-full shrink-0 flex-wrap/g)!.length,
    ).toBeGreaterThanOrEqual(3);
    expect(src).not.toContain("flex flex-shrink-0 items-center gap-2");
  });
});

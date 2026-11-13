import { describe, expect, it } from "vitest";
import { selectedRowClass } from "@/lib/utils";

describe("selectedRowClass (#4075)", () => {
  it("adds nothing for an unselected row", () => {
    expect(selectedRowClass(false)).toBe("");
  });

  it("tints a selected row with separate even and odd tokens", () => {
    const cls = selectedRowClass(true);
    expect(cls).toContain("even:!bg-[hsl(var(--row-selected-even))]");
    expect(cls).toContain("odd:!bg-[hsl(var(--row-selected-odd))]");
    expect(cls).not.toContain(
      "--row-selected-even))] odd:!bg-[hsl(var(--row-selected-even",
    );
  });

  it("keeps hover distinct and adds a left accent bar", () => {
    const cls = selectedRowClass(true);
    expect(cls).toContain("hover:!bg-[hsl(var(--row-selected-hover))]");
    expect(cls).toContain("inset_3px_0_0");
  });
});

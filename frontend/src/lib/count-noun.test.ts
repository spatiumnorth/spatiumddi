import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { countNoun } from "./count-noun";

describe("countNoun", () => {
  it("uses the singular for exactly one", () => {
    expect(countNoun(1, "space")).toBe("1 space");
    expect(countNoun(1, "entry", "entries")).toBe("1 entry");
  });
  it("uses the plural otherwise, including zero", () => {
    expect(countNoun(0, "space")).toBe("0 spaces");
    expect(countNoun(2, "entry", "entries")).toBe("2 entries");
  });
});

// Guard (#4780): the Overview glued a count to a fixed plural ("of 1
// subnets"). Fail if one of those lines comes back.
describe("DashboardPage count wording", () => {
  const src = readFileSync(
    resolve(__dirname, "../pages/DashboardPage.tsx"),
    "utf8",
  );
  it.each([
    "of ${total} subnets",
    "{data.api_tokens_total} tokens",
    "${c.node_count} nodes",
    "${h.container_count} containers",
    "{fw.policies_total} policies",
  ])("does not glue %s to a fixed plural", (bad) => {
    expect(src).not.toContain(bad);
  });
});

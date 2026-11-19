/**
 * @vitest-environment jsdom
 *
 * #4295 — the Manual upgrade dialog must not hardcode a Helm release name
 * (the chart default is not what operators install under) and must name
 * the namespace.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { ManualApplyModal } from "./ReleasesTab";

afterEach(cleanup);

describe("ManualApplyModal helm command", () => {
  it("uses release + namespace placeholders, not a bare release name", () => {
    render(<ManualApplyModal tag="1.0.0" onClose={() => {}} />);
    const cmd =
      Array.from(document.querySelectorAll("pre"))
        .map((p) => p.textContent ?? "")
        .find((t) => t.includes("helm upgrade")) ?? "";
    expect(cmd).toMatch(/helm upgrade <release>/);
    expect(cmd).toMatch(/-n <namespace>/);
    expect(cmd).not.toMatch(/helm upgrade spatiumddi/);
    expect(cmd).toContain("helm list -A");
    expect(cmd).toContain("--reuse-values");
    expect(cmd).toContain("--version 1.0.0");
  });
});

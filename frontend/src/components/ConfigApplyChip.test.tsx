/**
 * @vitest-environment jsdom
 *
 * ConfigApplyChip / ConfigApplyBanner on a partial apply (#1280).
 *
 * A PowerDNS agent that served every zone but one reports `reverted`, because
 * #882 has no partial status, with an error starting `partial apply: `. The
 * chip and banner used to say the agent "rolled back … NOT with what is saved
 * here": the opposite of what happened. These pin both readings, since the
 * difference is one string prefix and neither review nor `tsc` sees it.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ConfigApplyBanner, ConfigApplyChip } from "./ConfigApplyChip";
import { isPartialApply, PARTIAL_APPLY_PREFIX } from "@/lib/configApply";

afterEach(cleanup);

const PARTIAL = {
  config_apply_status: "reverted" as const,
  config_apply_error: `${PARTIAL_APPLY_PREFIX}the daemon refused 1 zone(s); every other zone is served: bad.test. create: HTTP 422 Duplicate record in RRset`,
  config_failed_etag: "sha256:live",
  config_apply_at: "2026-10-07T22:00:00.000Z",
};

const REVERTED = {
  ...PARTIAL,
  config_apply_error: "named-checkconf failed: zone x: bad owner name",
  config_failed_etag: "sha256:bad",
};

describe("partial apply", () => {
  it("is recognised only on reverted with the marker", () => {
    expect(isPartialApply("reverted", PARTIAL.config_apply_error)).toBe(true);
    expect(isPartialApply("reverted", REVERTED.config_apply_error)).toBe(false);
    expect(isPartialApply("revert_failed", PARTIAL.config_apply_error)).toBe(
      false,
    );
    expect(isPartialApply(null, null)).toBe(false);
  });

  it("chip says zones refused, not reverted, and names no rejected config", () => {
    render(<ConfigApplyChip server={PARTIAL} />);
    const chip = screen.getByText("Zones refused");
    const title = chip.getAttribute("title") ?? "";
    expect(title).toContain("nothing was rolled back");
    expect(title).toContain("bad.test.");
    expect(title).not.toContain(PARTIAL_APPLY_PREFIX);
    expect(title).not.toContain("Rejected config");
    expect(screen.queryByText("Config reverted")).toBeNull();
  });

  it("banner explains the partial apply and hides the live etag", () => {
    render(<ConfigApplyBanner server={PARTIAL} />);
    expect(screen.getByText("Zones refused")).toBeTruthy();
    expect(screen.getByText(/nothing was rolled back/)).toBeTruthy();
    expect(screen.queryByText(/rejected: sha256:live/)).toBeNull();
    expect(screen.queryByText(/NOT with what is saved/)).toBeNull();
  });

  it("a real revert still reads as one", () => {
    render(<ConfigApplyBanner server={REVERTED} />);
    expect(screen.getByText("Config reverted")).toBeTruthy();
    expect(
      screen.getByText(/rolled back to the last one that worked/),
    ).toBeTruthy();
    expect(screen.getByText(/rejected: sha256:bad/)).toBeTruthy();
  });
});

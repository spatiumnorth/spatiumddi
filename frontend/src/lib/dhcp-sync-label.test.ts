import { describe, expect, it } from "vitest";

import { syncLabel } from "./dhcp-sync-label";

const fmt = (s: string) => `<${s}>`;
const base = {
  last_sync_at: null,
  config_apply_status: null,
  config_apply_at: null,
};

describe("syncLabel", () => {
  it("shows the apply time for an applied agent-managed server", () => {
    expect(
      syncLabel(
        { ...base, config_apply_status: "ok", config_apply_at: "T1" },
        fmt,
      ),
    ).toBe("Config applied <T1>");
  });
  it("prefers the pull timestamp when there is one", () => {
    expect(
      syncLabel(
        {
          last_sync_at: "T0",
          config_apply_status: "ok",
          config_apply_at: "T1",
        },
        fmt,
      ),
    ).toBe("Last sync <T0>");
  });
  it("keeps Never synced for a server with no signal", () => {
    expect(syncLabel(base, fmt)).toBe("Never synced");
  });
  it("does not call a reverted or unreported apply a sync", () => {
    expect(
      syncLabel(
        { ...base, config_apply_status: "reverted", config_apply_at: "T1" },
        fmt,
      ),
    ).toBe("Never synced");
  });
});

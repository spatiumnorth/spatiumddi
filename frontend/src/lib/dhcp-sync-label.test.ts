import { describe, expect, it } from "vitest";

import { syncCard, syncLabel } from "./dhcp-sync-label";

const fmt = (s: string) => `<${s}>`;
const EARLIER = "2026-10-27T20:35:00.000Z";
const LATER = "2026-10-29T20:35:00.000Z";
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
  it("prefers the pull timestamp when it is the more recent", () => {
    expect(
      syncLabel(
        {
          last_sync_at: LATER,
          config_apply_status: "ok",
          config_apply_at: EARLIER,
        },
        fmt,
      ),
    ).toBe(`Last sync <${LATER}>`);
  });
  it("prefers a fresher apply report over a stale pull (#3046)", () => {
    expect(
      syncLabel(
        {
          last_sync_at: EARLIER,
          config_apply_status: "ok",
          config_apply_at: LATER,
        },
        fmt,
      ),
    ).toBe(`Config applied <${LATER}>`);
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

describe("syncCard (#3046)", () => {
  it("labels an applied agent-managed server's apply time as Config applied", () => {
    expect(
      syncCard({ ...base, config_apply_status: "ok", config_apply_at: "T1" }),
    ).toEqual({ label: "Config applied", at: "T1" });
  });

  it("has no time for a server that never synced or applied", () => {
    expect(syncCard(base)).toEqual({ label: "Last sync", at: null });
    expect(
      syncCard({
        ...base,
        config_apply_status: "reverted",
        config_apply_at: "T1",
      }),
    ).toEqual({ label: "Last sync", at: null });
  });

  it("labels the more recent of the two (#3046)", () => {
    expect(
      syncCard({
        last_sync_at: EARLIER,
        config_apply_status: "ok",
        config_apply_at: LATER,
      }),
    ).toEqual({ label: "Config applied", at: LATER });
    expect(
      syncCard({
        last_sync_at: LATER,
        config_apply_status: "ok",
        config_apply_at: EARLIER,
      }),
    ).toEqual({ label: "Last sync", at: LATER });
  });

  it("shows last_sync_at for an agentless server", () => {
    expect(syncCard({ ...base, last_sync_at: "T2" })).toEqual({
      label: "Last sync",
      at: "T2",
    });
  });
});

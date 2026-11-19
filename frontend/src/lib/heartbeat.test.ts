import { describe, expect, it } from "vitest";
import { isHeartbeatStale, silenceLabel } from "./heartbeat";

const NOW = Date.parse("2026-10-21T12:00:00Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();

describe("isHeartbeatStale", () => {
  it("is fresh within about three heartbeat intervals", () => {
    expect(isHeartbeatStale(ago(30_000), NOW)).toBe(false);
    expect(isHeartbeatStale(ago(89_000), NOW)).toBe(false);
  });
  it("is stale beyond three intervals", () => {
    expect(isHeartbeatStale(ago(91_000), NOW)).toBe(true);
    expect(isHeartbeatStale(ago(3 * 86_400_000), NOW)).toBe(true);
  });
  it("never-heartbeated or unparseable is not reported stale", () => {
    expect(isHeartbeatStale(null, NOW)).toBe(false);
    expect(isHeartbeatStale("garbage", NOW)).toBe(false);
  });
});

describe("silenceLabel", () => {
  it("renders minutes, hours and days", () => {
    expect(silenceLabel(ago(5 * 60_000), NOW)).toBe("5m");
    expect(silenceLabel(ago(3 * 3_600_000), NOW)).toBe("3h");
    expect(silenceLabel(ago(3 * 86_400_000), NOW)).toBe("3d");
  });
});

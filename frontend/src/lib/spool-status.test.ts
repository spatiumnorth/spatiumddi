import { describe, expect, it } from "vitest";

import type { AgentSpoolStatus, AgentSpoolStreamStatus } from "@/lib/api";
import { formatBytes, spoolState, TRIM_RECENT_MS } from "@/lib/spool-status";

const NOW = Date.parse("2026-09-22T12:00:00Z");

function stream(
  over: Partial<AgentSpoolStreamStatus> = {},
): AgentSpoolStreamStatus {
  return {
    enabled: true,
    entries: 0,
    bytes: 0,
    cap_bytes: 1000,
    oldest_at: null,
    trimmed_entries_total: 0,
    trimmed_bytes_total: 0,
    last_trim_at: null,
    expired_entries_total: 0,
    rejected_entries_total: 0,
    write_failures_total: 0,
    ...over,
  };
}

function status(over: Partial<AgentSpoolStatus> = {}): AgentSpoolStatus {
  return {
    enabled: true,
    cap_bytes: 268435456,
    bytes: 0,
    entries: 0,
    oldest_at: null,
    trimmed_entries_total: 0,
    trimmed_bytes_total: 0,
    last_trim_at: null,
    expired_entries_total: 0,
    streams: {},
    ...over,
  };
}

describe("spoolState", () => {
  it("treats null (never reported) as nothing to show, not healthy", () => {
    expect(spoolState(null, NOW)).toEqual({ kind: "none" });
    expect(spoolState(undefined, NOW)).toEqual({ kind: "none" });
  });

  it("shows nothing for an empty spool with no recent trim", () => {
    expect(spoolState(status(), NOW).kind).toBe("none");
  });

  it("reports a backlog while bytes are queued", () => {
    const s = spoolState(
      status({
        bytes: 3355443,
        entries: 12,
        oldest_at: "2026-09-22T11:00:00Z",
      }),
      NOW,
    );
    expect(s).toEqual({
      kind: "backlog",
      bytes: 3355443,
      entries: 12,
      oldestAt: "2026-09-22T11:00:00Z",
    });
  });

  it("a recent trim outranks a backlog and names the trimmed streams", () => {
    const recent = new Date(NOW - 60_000).toISOString();
    const s = spoolState(
      status({
        bytes: 500,
        last_trim_at: recent,
        streams: {
          metrics: stream({
            last_trim_at: new Date(NOW - 2 * TRIM_RECENT_MS).toISOString(),
          }),
          lease_events: stream({ last_trim_at: recent }),
        },
      }),
      NOW,
    );
    expect(s.kind).toBe("trimmed");
    if (s.kind === "trimmed") expect(s.streams).toEqual(["lease_events"]);
  });

  it("a trim older than 24 h no longer counts", () => {
    const old = new Date(NOW - TRIM_RECENT_MS - 1000).toISOString();
    expect(spoolState(status({ last_trim_at: old }), NOW).kind).toBe("none");
  });
});

describe("formatBytes", () => {
  it("scales", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(3355443)).toBe("3.2 MB");
  });
});

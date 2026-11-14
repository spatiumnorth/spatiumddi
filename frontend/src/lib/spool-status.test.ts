import { describe, expect, it } from "vitest";

import type { AgentSpoolStatus, AgentSpoolStreamStatus } from "@/lib/api";
import {
  formatBytes,
  formatCount,
  spoolState,
  TRIM_RECENT_MS,
} from "@/lib/spool-status";

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

  it("shows the lease backlog of an agent that is falling behind (#3782)", () => {
    const st = spoolState(
      status({
        pending_events: 2400,
        pending_lag_seconds: 300,
        unread_bytes: 4096,
        unread_events_estimated: 2000,
      }),
      NOW,
    );
    expect(st).toEqual({
      kind: "pending",
      events: 2400,
      estimated: 2000,
      unreadBytes: 4096,
      lagSeconds: 300,
    });
    // Absent / null counts are unknown, not a backlog.
    expect(spoolState(status({ pending_events: null }), NOW).kind).toBe("none");
    // A durable backlog still outranks the pending report.
    expect(
      spoolState(status({ bytes: 10, entries: 1, pending_events: 5 }), NOW)
        .kind,
    ).toBe("backlog");
  });

  it("a steady, healthy agent shows no chip however stale its heartbeat is (#3782)", () => {
    // 20-89 events held at every heartbeat, lag a few seconds as of the report.
    // The heartbeat being 30 s old on the page's clock must not matter.
    const stale = new Date(NOW - 30_000).toISOString();
    for (const [events, lag] of [
      [20, 2],
      [66, 9.6],
      [89, 25],
      [500, 59],
    ]) {
      expect(
        spoolState(
          status({
            pending_events: events,
            pending_lag_seconds: lag,
            pending_oldest_at: stale,
            last_trim_at: null,
          }),
          NOW + 120_000,
        ).kind,
      ).toBe("none");
    }
  });

  it("a growing backlog shows, and tiny ones do not (#3782)", () => {
    const at = (events: number, lag: number) =>
      spoolState(
        status({ pending_events: events, pending_lag_seconds: lag }),
        NOW,
      ).kind;
    expect(at(1257, 79)).toBe("pending");
    expect(at(1648, 220)).toBe("pending");
    expect(at(3, 600)).toBe("none");
  });

  it("an agent that reports no pending fields (1.0.0-rc.2) shows no chip (#3782)", () => {
    expect(
      spoolState(
        status({
          pending_events: null,
          pending_lag_seconds: null,
          pending_oldest_at: null,
        }),
        NOW,
      ).kind,
    ).toBe("none");
    expect(spoolState(status(), NOW).kind).toBe("none");
  });

  it("prints counts with a thousands separator (#3782)", () => {
    expect(formatCount(1928)).toBe("1,928");
    expect(formatCount(20)).toBe("20");
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

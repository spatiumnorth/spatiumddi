import { describe, expect, it } from "vitest";
import { readZoneSerials } from "./zoneSerials";
import { PARTIAL_APPLY_PREFIX } from "@/lib/configApply";

const srv = (id: string, refused = false) => ({
  id,
  config_apply_status: refused ? ("reverted" as const) : ("ok" as const),
  config_apply_error: refused ? `${PARTIAL_APPLY_PREFIX}x` : null,
});
const sum = (drift = 0, not_reported = 0, total = 6) => ({
  total,
  in_sync: total - drift - not_reported,
  drift,
  not_reported,
});

describe("readZoneSerials", () => {
  it("says no zones", () => {
    expect(
      readZoneSerials({ zoneCount: 0, servers: [srv("a")], summaries: {} })
        .text,
    ).toBe("no zones");
  });

  it("reports in sync only when every server reported and matches", () => {
    const r = readZoneSerials({
      zoneCount: 6,
      servers: [srv("a"), srv("b")],
      summaries: { a: sum(), b: sum() },
    });
    expect(r).toEqual({ text: "6 zones · in sync on 2 servers", tone: "ok" });
    expect(r.text).not.toMatch(/assumed|Wave/);
  });

  it("counts servers that are behind or refused zones", () => {
    const r = readZoneSerials({
      zoneCount: 6,
      servers: [srv("a"), srv("b", true)],
      summaries: { a: sum(2), b: sum() },
    });
    expect(r.tone).toBe("warn");
    expect(r.text).toBe("6 zones · 1 server behind · 1 server refused zones");
  });

  it("says no servers for a group with zones and none", () => {
    expect(
      readZoneSerials({ zoneCount: 2, servers: [], summaries: {} }),
    ).toEqual({ text: "2 zones · no servers", tone: "muted" });
  });

  it("does not call a loading rollup unreadable or in sync", () => {
    const r = readZoneSerials({
      zoneCount: 2,
      servers: [srv("a"), srv("b")],
      summaries: { a: sum() },
      failed: new Set(),
    });
    expect(r).toEqual({
      text: "2 zones · per-server serials not loaded",
      tone: "muted",
    });
  });

  it("calls only a failed rollup unreadable", () => {
    const r = readZoneSerials({
      zoneCount: 2,
      servers: [srv("a"), srv("b")],
      summaries: { a: sum() },
      failed: new Set(["b"]),
    });
    expect(r).toEqual({
      text: "2 zones · 1 server unreadable",
      tone: "warn",
    });
  });

  it("shows a known problem while another server is still loading", () => {
    const r = readZoneSerials({
      zoneCount: 6,
      servers: [srv("a"), srv("b")],
      summaries: { a: sum(1) },
      failed: new Set(),
    });
    expect(r).toEqual({ text: "6 zones · 1 server behind", tone: "warn" });
  });

  it("says plainly when servers have not reported", () => {
    const r = readZoneSerials({
      zoneCount: 1,
      servers: [srv("a"), srv("b")],
      summaries: { a: sum(0, 1, 1) },
      failed: new Set(["b"]),
    });
    expect(r.tone).toBe("warn");
    expect(r.text).toBe(
      "1 zone · 1 server not reported on every zone yet · 1 server unreadable",
    );
  });

  it("does not claim sync before anything is loaded", () => {
    const r = readZoneSerials({
      zoneCount: 3,
      servers: [srv("a")],
      summaries: {},
    });
    expect(r.tone).toBe("muted");
    expect(r.text).not.toMatch(/in sync/);
  });
});

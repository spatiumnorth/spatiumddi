// @vitest-environment jsdom
// #3940 — a secondary zone's serial is its primary's, so the pill must use the
// API's per-server verdict and show the served serial, not the target (0).
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ZoneServerState } from "@/lib/api";

afterEach(cleanup);

const { ZoneSyncPill } = await import("./DNSPage");

function pill(state: ZoneServerState) {
  const qc = new QueryClient();
  const { container } = render(
    <QueryClientProvider client={qc}>
      <ZoneSyncPill state={state} />
    </QueryClientProvider>,
  );
  const el = container.querySelector("span")!;
  return { text: el.textContent ?? "", title: el.getAttribute("title") ?? "" };
}

function state(
  zone_type: string,
  target: number,
  serial: number,
  inSync: boolean,
): ZoneServerState {
  return {
    zone_id: "z",
    zone_name: "example.com.",
    zone_type,
    target_serial: target,
    in_sync: inSync,
    servers: [
      {
        server_id: "s1",
        server_name: "ns1",
        server_status: "active",
        current_serial: serial,
        reported_at: null,
        pending_ops: 0,
        freshness: "ok",
        counted: true,
        in_sync: inSync,
      },
    ],
  };
}

describe("ZoneSyncPill on a transferred secondary (#3940)", () => {
  it("counts the API's in_sync and shows the served serial", () => {
    const { text, title } = pill(state("secondary", 0, 2026111302, true));
    expect(text).toBe("1/1 synced · serial 2026111302");
    expect(title).not.toContain("drift");
  });

  it("reads drift for a secondary the API says is not in sync", () => {
    const { text } = pill(state("secondary", 0, 0, false));
    expect(text).toBe("1/1 drift");
  });

  it("leaves a primary zone as it was", () => {
    expect(pill(state("primary", 42, 42, true)).text).toBe(
      "1/1 synced · serial 42",
    );
    expect(pill(state("primary", 42, 41, false)).text).toBe(
      "1/1 drift · target 42",
    );
  });
});

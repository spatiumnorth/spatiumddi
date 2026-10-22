import { describe, expect, it } from "vitest";
import {
  classifyIpDnsState,
  isDefaultGatewayHostname,
  isDefaultGatewayHostnameInput,
  staleReasonKeepsAddress,
  staleReasonText,
} from "./gatewayDns";

const base = {
  status: "allocated",
  hostname: "gateway",
  subnetHasDnsZone: true,
  hasForwardZone: true,
  outOfSync: false,
};

describe("classifyIpDnsState", () => {
  it("shows forward-skipped for a gateway host in a subnet with a forward zone", () => {
    expect(classifyIpDnsState(base)).toBe("forward-skipped");
  });
  it("stays n/a when there is no forward zone to skip", () => {
    expect(classifyIpDnsState({ ...base, hasForwardZone: false })).toBe("n/a");
  });
  it("stays n/a when the subnet has no DNS at all", () => {
    expect(classifyIpDnsState({ ...base, subnetHasDnsZone: false })).toBe(
      "n/a",
    );
  });
  it("reports a leftover forward record on a gateway host as out of sync", () => {
    expect(classifyIpDnsState({ ...base, outOfSync: true })).toBe(
      "out-of-sync",
    );
  });
  it("only matches the exact hostname", () => {
    expect(classifyIpDnsState({ ...base, hostname: "gateway2" })).toBe(
      "in-sync",
    );
    expect(classifyIpDnsState({ ...base, hostname: "my-gateway" })).toBe(
      "in-sync",
    );
    expect(isDefaultGatewayHostname("gw")).toBe(false);
  });
  it("matches a stored hostname exactly, as the backend does", () => {
    // The backend compares ``ip.hostname == "gateway"``; a row an integration
    // wrote as "Gateway" is published, so it must not read as skipped.
    expect(classifyIpDnsState({ ...base, hostname: "Gateway" })).toBe(
      "in-sync",
    );
  });
  it("normalises typed input the way the API will store it", () => {
    for (const h of ["gateway", " gateway ", "Gateway", "GATEWAY.", "gateway."])
      expect(isDefaultGatewayHostnameInput(h)).toBe(true);
    for (const h of ["gateway2", "my-gateway", "gateway.lab", "gw", "", null])
      expect(isDefaultGatewayHostnameInput(h)).toBe(false);
  });
  it("counts a stale-pending row as out of sync", () => {
    expect(
      classifyIpDnsState({ ...base, hostname: "web1", outOfSync: true }),
    ).toBe("out-of-sync");
  });
});

describe("staleReasonText", () => {
  it("explains the gateway rule in words, not the raw code", () => {
    const t = staleReasonText("default-gateway-name");
    expect(t).toMatch(/named exactly 'gateway'/);
    expect(t).not.toBe("default-gateway-name");
    expect(staleReasonKeepsAddress("default-gateway-name")).toBe(true);
  });
  it("explains no-forward-zone and ip-deleted", () => {
    expect(staleReasonText("no-forward-zone")).toMatch(/no forward zone/);
    expect(staleReasonKeepsAddress("ip-deleted")).toBe(false);
  });
  it("falls back to the code for an unknown reason", () => {
    expect(staleReasonText("brand-new")).toContain("brand-new");
  });
});

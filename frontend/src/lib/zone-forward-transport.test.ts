import { describe, expect, it } from "vitest";

import {
  zoneTransportError,
  zoneTransportOptions,
} from "./zone-forward-transport";

describe("zoneTransportOptions (#2121)", () => {
  it("offers plain DNS and DoT on BIND9, and on an empty group", () => {
    expect(zoneTransportOptions(["bind9"])).toEqual(["do53", "tls"]);
    expect(zoneTransportOptions([])).toEqual(["do53", "tls"]);
  });

  it("offers DoH and DoQ only when every server is Technitium", () => {
    expect(zoneTransportOptions(["technitium"])).toEqual([
      "do53",
      "tls",
      "https",
      "quic",
    ]);
    expect(zoneTransportOptions(["bind9", "technitium"])).toEqual([
      "do53",
      "tls",
    ]);
  });

  it("offers plain DNS only where no driver forwards over TLS", () => {
    expect(zoneTransportOptions(["windows_dns"])).toEqual(["do53"]);
  });
});

describe("zoneTransportError (#2121)", () => {
  it("never refuses plain DNS", () => {
    expect(zoneTransportError("do53", "", ["bind9"])).toBeNull();
  });

  it("requires a hostname for an encrypted transport", () => {
    expect(zoneTransportError("tls", "", ["bind9"])).toMatch(/required/);
    expect(zoneTransportError("tls", "dns.quad9.net", ["bind9"])).toBeNull();
  });

  it("refuses a hostname that is not a host name", () => {
    expect(zoneTransportError("tls", 'x"; };', ["bind9"])).toMatch(
      /TLS hostname/,
    );
  });

  it("refuses DoH on a BIND9 group", () => {
    expect(zoneTransportError("https", "dns.quad9.net", ["bind9"])).toMatch(
      /not supported/,
    );
  });
});

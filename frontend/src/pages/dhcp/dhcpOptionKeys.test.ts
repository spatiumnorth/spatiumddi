import { describe, expect, it } from "vitest";
import { optionKeyCode, optionsFromMap, optionsToMap } from "./dhcpOptionKeys";

describe("option keys for map-shaped stores (#1228)", () => {
  it("keys a catalogue pick by the raw code, not its IANA name", () => {
    expect(
      optionsToMap([
        { code: 43, name: "vendor-encapsulated-options", value: "0104" },
        { code: 3, name: "routers", value: ["10.0.0.1"] },
        { code: 6, name: "domain-name-servers", value: ["10.0.0.2"] },
        { code: 252, value: "x" },
      ]),
    ).toEqual({
      "code:43": "0104",
      routers: ["10.0.0.1"],
      "dns-servers": ["10.0.0.2"],
      "code:252": "x",
    });
  });

  it("keeps a retyped code on a raw-code row", () => {
    expect(
      optionsToMap([{ code: 132, name: "code:43", value: "100" }]),
    ).toEqual({ "code:132": "100" });
  });

  it("reads stored keys back under their code, and round-trips", () => {
    const stored = { "code:43": "0104", mtu: "9000", "opt-252": "x" };
    const rows = optionsFromMap(stored);
    expect(rows.map((r) => r.code)).toEqual([43, 26, 252]);
    expect(optionsToMap(rows)).toEqual(stored);
    expect(optionKeyCode("netbios-name-servers")).toBe(0);
  });
});

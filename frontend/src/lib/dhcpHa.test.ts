import { describe, expect, it } from "vitest";

import {
  HA_V4_ONLY_NOTE,
  haPillTitle,
  v6ScopeLacksHa,
  v6ScopeNoHaNote,
} from "./dhcpHa";

describe("v6ScopeLacksHa (#1238)", () => {
  const pair = { kea_member_count: 2 };

  it("flags a DHCPv6 scope on a group with two Kea members", () => {
    expect(v6ScopeLacksHa({ address_family: "ipv6" }, pair)).toBe(true);
  });

  it("flags a third member too — backups do not make v6 coordinated", () => {
    expect(
      v6ScopeLacksHa({ address_family: "ipv6" }, { kea_member_count: 3 }),
    ).toBe(true);
  });

  it("leaves a DHCPv4 scope alone, which HA does cover", () => {
    expect(v6ScopeLacksHa({ address_family: "ipv4" }, pair)).toBe(false);
    // An older API row with no family is a v4 scope.
    expect(v6ScopeLacksHa({}, pair)).toBe(false);
  });

  it("leaves a scope that allocates no addresses alone", () => {
    // stateless = options only, slaac = nothing rendered: no address for
    // two members to hand out twice.
    expect(
      v6ScopeLacksHa(
        { address_family: "ipv6", v6_address_mode: "stateless" },
        pair,
      ),
    ).toBe(false);
    expect(
      v6ScopeLacksHa(
        { address_family: "ipv6", v6_address_mode: "slaac" },
        pair,
      ),
    ).toBe(false);
    expect(
      v6ScopeLacksHa(
        { address_family: "ipv6", v6_address_mode: "stateful" },
        pair,
      ),
    ).toBe(true);
  });

  it("leaves a disabled scope alone: it is not in the bundle", () => {
    expect(
      v6ScopeLacksHa({ address_family: "ipv6", enabled: false }, pair),
    ).toBe(false);
  });

  it("leaves a single-Kea group alone: one server needs no coordination", () => {
    expect(
      v6ScopeLacksHa({ address_family: "ipv6" }, { kea_member_count: 1 }),
    ).toBe(false);
  });

  it("does not flag on a guess while the group is unknown", () => {
    expect(v6ScopeLacksHa({ address_family: "ipv6" }, undefined)).toBe(false);
    expect(v6ScopeLacksHa({ address_family: "ipv6" }, null)).toBe(false);
  });
});

describe("HA wording (#1238)", () => {
  it("every HA pill tooltip says HA is DHCPv4 only", () => {
    expect(haPillTitle(null)).toContain(HA_V4_ONLY_NOTE);
    expect(haPillTitle("2026-09-30T10:00:00.000Z")).toContain(HA_V4_ONLY_NOTE);
    expect(haPillTitle(null)).toContain("No HA heartbeat received yet");
  });

  it("the v6 note names the member count and a way out", () => {
    const note = v6ScopeNoHaNote(2);
    expect(note).toContain("2 Kea members");
    expect(note).toContain("DHCPv4 only");
    expect(note).toContain("one Kea member");
  });
});

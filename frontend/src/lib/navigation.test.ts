/**
 * Nav gating + ordering (#1068).
 *
 * Two things worth pinning, both found the hard way:
 *
 * 1. Order must survive a disable/enable cycle. `filterNav` preserves array
 *    order today, but "the sidebar reshuffled itself" is exactly the kind of
 *    report that is hard to confirm by reading code, so assert it.
 * 2. A `module` tag on a nav entry is inert unless the renderer actually
 *    filters that group. `dnsSectionNav` carried tags that `Sidebar` never
 *    applied, so with core.dns off its heading rendered over a single
 *    ungated row — the "written, never read" class the #899 audit named,
 *    one layer up in the UI.
 */

import { describe, expect, it } from "vitest";
import {
  baseMainNav,
  coreIpamNav,
  dnsSectionNav,
  filterNav,
  integrationsNav,
  networkInfrastructureNav,
  networkLogicalNav,
  type NavEntry,
} from "./navigation";

const labels = (items: NavEntry[], on: Set<string>) =>
  filterNav(items, (id) => on.has(id)).map((i) => i.label);

const ALL_ON = new Set(["core.dhcp", "core.dns", "governance.requests"]);

describe("core nav ordering", () => {
  it("restores the original order after a disable/enable cycle", () => {
    for (const off of ["core.dhcp", "core.dns"]) {
      const before = labels(baseMainNav, ALL_ON);
      const partial = new Set([...ALL_ON].filter((m) => m !== off));
      const during = labels(baseMainNav, partial);
      const after = labels(baseMainNav, ALL_ON);

      expect(during.length).toBe(before.length - 1);
      expect(after).toEqual(before);
    }
  });

  it("keeps DHCP and DNS in their declared slots, not appended", () => {
    expect(labels(baseMainNav, ALL_ON).slice(0, 4)).toEqual([
      "Dashboard",
      "IPAM",
      "DHCP",
      "DNS",
    ]);
  });
});

describe("module tags on sub-groups are live, not decorative", () => {
  it("the DNS sub-group empties out when core.dns is off", () => {
    const on = new Set(["core.dhcp", "governance.requests", "network.domains"]);
    const remaining = labels(dnsSectionNav, on);
    // Domains is not gated on core.dns — a registrar record outlives any
    // zone we serve — so it survives while its own module (#2325) is on.
    expect(remaining).toEqual(["Domains"]);
    expect(labels(dnsSectionNav, new Set(["core.dhcp"]))).toEqual([]);
    expect(remaining).not.toContain("DNS Pools");
    expect(remaining).not.toContain("DNSSEC Policies");
  });

  it("the IPAM sub-group loses only NAT Mappings when ipam.nat is off (#2100)", () => {
    const off = labels(coreIpamNav, new Set());
    expect(off).not.toContain("NAT Mappings");
    // Everything else under IPAM is ungated, so the heading never empties.
    expect(off.length).toBe(coreIpamNav.length - 1);
    expect(labels(coreIpamNav, new Set(["ipam.nat"]))).toContain(
      "NAT Mappings",
    );
  });
});

describe("Network Devices (SNMP) lives under Integrations (#4656)", () => {
  const route = "/network/devices";
  const find = (items: NavEntry[]) =>
    items.find((i) => "to" in i && i.to === route);

  it("is an integrationsNav entry on its own network.device gate", () => {
    const e = find(integrationsNav);
    expect(e?.label).toBe("Network Devices (SNMP)");
    expect(e?.module).toBe("network.device");
  });

  it("is no longer in either Network list", () => {
    expect(find(networkInfrastructureNav)).toBeUndefined();
    expect(find(networkLogicalNav)).toBeUndefined();
  });

  it("sits in alphabetical order among the integrations", () => {
    const ls = integrationsNav.map((i) => i.label);
    expect(ls).toEqual(
      [...ls].sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" })),
    );
  });
});

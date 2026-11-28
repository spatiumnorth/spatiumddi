/**
 * An instruction that names a control is drawn only for a user the control is
 * offered to (#4588, the sites #4314 / #4320 did not reach).
 *
 * A shape test, not a fixed render list: every instruction below is found in
 * its source file and must sit inside the gate of the control it names, so a
 * revert of any one of them fails here. Adding a site means adding a row.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const src = (rel: string) =>
  readFileSync(resolve(__dirname, "..", rel), "utf8");

// [site, file, instruction fragment, gate expression that must wrap it]
const sites: Array<[string, string, string, RegExp]> = [
  [
    "Platform Insights conformity",
    "pages/admin/PlatformInsightsPage.tsx",
    "Toggle a policy on in",
    /canToggle/,
  ],
  [
    "Dashboard RPKI tiles",
    "pages/DashboardPage.tsx",
    "Add a public ASN and the hourly refresh",
    /canAddAsn\s*\?/,
  ],
  [
    "ASN Communities",
    "pages/network/CommunitiesTab.tsx",
    'use the "Use on this AS" button',
    /!writeGate\.disabled/,
  ],
  [
    "Responders",
    "pages/dhcp/DHCPPage.tsx",
    "acknowledge a known-but-external one",
    /!ackGate\.disabled/,
  ],
  [
    "Router advertisements",
    "pages/dhcp/DHCPPage.tsx",
    "acknowledge an expected one",
    /!ackGate\.disabled/,
  ],
  [
    "Subnet Aliases",
    "pages/ipam/IPAMPage.tsx",
    "Add aliases from the IP address edit",
    /canAdd &&/,
  ],
  [
    "PXE profiles",
    "pages/dhcp/PXEProfilesPage.tsx",
    "bind a profile to a",
    /perms\.can\("write", "dhcp_scope"\)/,
  ],
  [
    "IP network discovery",
    "pages/ipam/IPNetworkTab.tsx",
    "add the upstream switch in",
    /canAddDevice/,
  ],
  [
    "Overlay policies",
    "pages/network/OverlayDetailPage.tsx",
    "create one to override the default path strategy",
    /!writeGate\.disabled/,
  ],
  [
    "BGP monitoring",
    "pages/network/BgpMonitorTab.tsx",
    "you can also add one manually",
    /!writeGate\.disabled/,
  ],
  [
    "Subnet Planner how-to",
    "pages/ipam/SubnetPlannerEditorPage.tsx",
    "Save, then Apply to materialise",
    /!applyGate\.disabled/,
  ],
  [
    "Gateway note advice",
    "lib/gatewayDns.ts",
    "Rename it (e.g. 'gw'",
    /GATEWAY_FORWARD_SKIPPED_ADVICE/,
  ],
  [
    "T1 IPAM-made record",
    "pages/dns/DNSPage.tsx",
    "Edit the IP address in IPAM to change it",
    /can\("write", "subnet"\)/,
  ],
  [
    "T2 legacy tag (subnet)",
    "pages/ipam/IPAMPage.tsx",
    "assign a Router/VLAN from the Edit modal to manage",
    /canEditSubnet \?/,
  ],
  [
    "T2 legacy tag (block, space)",
    "pages/ipam/IPAMPage.tsx",
    'assign a Router/VLAN from the Edit modal"',
    /canWriteSubnets \?/,
  ],
  [
    "T3 alias count",
    "pages/ipam/IPAMPage.tsx",
    "edit IP to view",
    /canEdit \?/,
  ],
  [
    "T4 DNS drift",
    "pages/ipam/IPAMPage.tsx",
    "open Sync DNS to reconcile",
    /canDnsSync \?/,
  ],
  [
    "T5 sites tree",
    "pages/network/SitesPage.tsx",
    "(drag to re-parent)",
    /writeGate\.disabled/,
  ],
  [
    "T6 block with children",
    "pages/ipam/IPAMPage.tsx",
    "delete those first",
    /selectionDeleteGateFor\(perms, true, true\)\.disabled/,
  ],
  [
    "T7 UniFi Edit link",
    "pages/unifi/UnifiControllerDetailPage.tsx",
    "Edit on the UniFi list page",
    /!superadminGate\.disabled/,
  ],
  [
    "MAC lookup OUI",
    "pages/tools/NetworkToolsPage.tsx",
    "Enable it under Settings",
    /isSuperadmin/,
  ],
  [
    "E911 module off",
    "pages/network/E911Page.tsx",
    "Enable it under Features & Integrations",
    /isSuperadmin/,
  ],
];

describe("an instruction is drawn only inside its control's gate (#4588)", () => {
  it.each(sites)("%s", (_site, file, fragment, gate) => {
    const text = src(file);
    const at = text.indexOf(fragment);
    expect(at, `${fragment} is in ${file}`).toBeGreaterThan(-1);
    // The gate opens within the few lines before the sentence.
    const window = text.slice(Math.max(0, at - 450), at);
    expect(window).toMatch(gate);
  });

  it("the Calendars intro no longer tells every reader to subscribe", () => {
    expect(src("pages/tools/WakeSchedulesPage.tsx")).not.toContain(
      "Subscribe a holiday / term calendar",
    );
  });
});

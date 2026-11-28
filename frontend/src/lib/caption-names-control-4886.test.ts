// Guard for #4886: a field whose caption is drawn as text above the control
// (not a <label>) must still name it. #4778 tied every <label>; these sixteen
// captions were a <p>, <span> or <summary> and the control had no id, no
// aria-label and no aria-labelledby, so it was announced by its placeholder
// or by nothing. Each site is a [file, caption, how the control is named]:
// "for:<id>" needs a <label htmlFor=id> holding the caption and a control with
// that id; "aria:<text>" needs an aria-label on a control.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const PAGES = join(__dirname, "..", "pages");

const SITES: [string, string, string][] = [
  ["ipam/IPAMPage.tsx", "DNS Server Group", "for:dnsGroupSelectId"],
  ["ipam/IPAMPage.tsx", "Primary Zone", "for:primaryZoneSelectId"],
  ["ipam/IPAMPage.tsx", "DHCP Server Group", "for:dhcpGroupSelectId"],
  [
    "dns/DNSPage.tsx",
    "Match clients (one per line; prefix ! to negate)",
    "for:dns-view-match-clients",
  ],
  [
    "dns/DNSPage.tsx",
    "Match destinations (advanced)",
    "aria:Match destinations (advanced)",
  ],
  [
    "dns/DNSPage.tsx",
    "One domain per line. Duplicates and invalid entries are skipped.",
    "for:dns-bulk-domains",
  ],
  [
    "AccountPage.tsx",
    "Enter the 6-digit code from your authenticator to confirm:",
    "for:account-totp-confirm-code",
  ],
  ["AccountPage.tsx", "{providerName", "for:account-2fa-setup-password"],
  ["appliance/NetworkTab.tsx", "Control-plane VIP", "for:net-cp-vip"],
  [
    "appliance/NetworkTab.tsx",
    "DNS resolver VIP (:53) — optional",
    "for:net-dns-vip",
  ],
  [
    "appliance/NetworkTab.tsx",
    "DHCP relay VIP (:67) — optional",
    "for:net-dhcp-relay-vip",
  ],
  [
    "appliance/NetworkTab.tsx",
    "Peer address",
    "for:`net-bgp-peer-address-${i}`",
  ],
  ["appliance/NetworkTab.tsx", "Peer ASN", "for:`net-bgp-peer-asn-${i}`"],
  ["appliance/NetworkTab.tsx", "My ASN", "for:`net-bgp-my-asn-${i}`"],
  [
    "appliance/FleetTab.tsx",
    "One CIDR or IP per line. Each entry opens",
    "for:fleet-kubeapi-source-ranges",
  ],
  ["network/MulticastGroupsPage.tsx", "Attach a producer", "aria:Role"],
];

describe("captions name their control (#4886)", () => {
  for (const [file, caption, how] of SITES) {
    it(`${file}: ${caption}`, () => {
      const src = readFileSync(join(PAGES, file), "utf8");
      const kind = how.slice(0, how.indexOf(":"));
      const value = how.slice(how.indexOf(":") + 1);
      if (kind === "for") {
        const quoted =
          /^[a-z]+Id$|^`/.test(value) || value.endsWith("SelectId")
            ? `{${value}}`
            : `"${value}"`;
        const label = new RegExp(
          `<label[^>]*htmlFor=${quoted.replace(/[$.{}()]/g, "\\$&")}[^>]*>\\s*${caption.replace(/[.()?{]/g, "\\$&")}`,
        );
        expect(src).toMatch(label);
        const id = `id=${quoted}`;
        expect(src.split(id).length - 1).toBeGreaterThanOrEqual(1);
      } else {
        expect(src).toContain(`aria-label="${value}"`);
      }
    });
  }
});

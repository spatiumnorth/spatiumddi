import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { GRANT_RESOURCE_TYPES } from "./permissionVocabulary";

// The resource types the built-in roles grant (GET /roles, is_builtin), which
// a custom role must be able to carry too (#2439).
const BUILTIN_ROLE_TYPES = [
  "appliance",
  "av_flow",
  "bacnet_device",
  "dhcp_mac_block",
  "dhcp_option_template",
  "dicom_ae",
  "dnsbl",
  "e911_location",
  "manage_asns",
  "manage_domains",
  "manage_block_sync",
  "manage_dns_pools",
  "manage_network_devices",
  "manage_nmap_scans",
  "manage_packet_capture",
  "multicast",
  "nat_mapping",
  "ot_device",
  "provisioning_request",
  "tls_cert",
  "use_network_tools",
];

describe("GRANT_RESOURCE_TYPES", () => {
  const offered = new Set<string>(GRANT_RESOURCE_TYPES);

  it("offers every type a built-in role grants", () => {
    expect(BUILTIN_ROLE_TYPES.filter((t) => !offered.has(t))).toEqual([]);
  });

  it("offers every type in docs/PERMISSIONS.md's resource table", () => {
    const md = readFileSync(
      resolve(__dirname, "../../../docs/PERMISSIONS.md"),
      "utf8",
    );
    const section = md.split("### Resource types")[1].split("## Evaluation")[0];
    const documented = [...section.matchAll(/^\| `([a-z_*]+)`/gm)].map(
      (m) => m[1],
    );
    expect(documented.length).toBeGreaterThan(40);
    expect(
      documented.filter((t) => t !== "resource_type" && !offered.has(t)),
    ).toEqual([]);
  });

  it("offers no type that no route checks (#2621)", () => {
    // The ASN and Domains routes check manage_asns / manage_domains by exact
    // match, so a grant on `asn` or `domain` reads nothing.
    expect(offered.has("asn")).toBe(false);
    expect(offered.has("domain")).toBe(false);
  });

  it("has no duplicates", () => {
    expect(offered.size).toBe(GRANT_RESOURCE_TYPES.length);
  });
});

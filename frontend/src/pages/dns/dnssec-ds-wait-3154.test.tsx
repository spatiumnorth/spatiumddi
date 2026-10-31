/**
 * @vitest-environment jsdom
 *
 * The DNSSEC card's wait for DS records says what each signer does (#3154).
 *
 * A signed zone with no DS yet read "Waiting for the agent to report DS
 * records (typically <30 s after signing)". That holds for PowerDNS, whose
 * sign op returns the DS. The BIND9 agent reports a key's DS only once BIND's
 * key state makes it submittable (DSState rumoured or omnipresent,
 * `_DS_SUBMITTABLE_STATES` in agent/dns/spatium_dns_agent/drivers/bind9.py),
 * which under the default policy is about a day after signing.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSZone, ZoneDnssecInfo } from "@/lib/api";

const pending = () => new Promise<never>(() => {});
let dnssecInfo: ZoneDnssecInfo | null = null;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, myPermissions: pending },
    dnsApi: {
      ...actual.dnsApi,
      classifyZoneName: pending,
      listGroups: () =>
        Promise.resolve([{ id: "grp-1", server_drivers: ["bind9"] }]),
      getZoneDnssecInfo: () => Promise.resolve(dnssecInfo),
      listDnssecPolicies: () => Promise.resolve([]),
    },
    domainsApi: { ...actual.domainsApi, list: pending },
    customersApi: { ...actual.customersApi, list: pending },
    settingsApi: { ...actual.settingsApi, get: pending },
  };
});

vi.mock("@/hooks/useFeatureModules", async () => {
  const actual = await vi.importActual<
    typeof import("@/hooks/useFeatureModules")
  >("@/hooks/useFeatureModules");
  return {
    ...actual,
    useFeatureModules: () => ({ ready: true, enabled: () => true }),
  };
});

const { ZoneModal } = await import("./DNSPage");

const ZONE = {
  id: "zone-1",
  group_id: "grp-1",
  view_id: null,
  name: "signed.example.test.",
  zone_type: "primary",
  kind: "forward",
  ttl: 3600,
  primary_ns: "ns1.signed.example.test.",
  admin_email: "hostmaster.signed.example.test.",
  dnssec_enabled: true,
  color: null,
  forwarders: [],
  forward_only: false,
  masters: [],
  domain_id: null,
  customer_id: null,
} as unknown as DNSZone;

// What the API returns minutes after a BIND9 zone is signed: the agent has
// reported the zone's key, and no DS, because BIND has not made it
// submittable yet.
const SIGNED_NO_DS: ZoneDnssecInfo = {
  zone_id: "zone-1",
  zone_name: "signed.example.test.",
  dnssec_enabled: true,
  dnssec_policy_id: null,
  dnssec_ds_records: [],
  dnssec_synced_at: "2026-10-31T05:51:40Z",
  keys: [
    {
      key_tag: 46314,
      key_type: "csk",
      algorithm: 13,
      algorithm_name: "ECDSAP256SHA256",
      state: "active",
      ds_records: [],
    },
  ],
  dnssec_multi_signer: false,
  signing_servers: 1,
  signing_unmanaged: false,
};

afterEach(() => {
  cleanup();
  dnssecInfo = null;
});

describe("the DNSSEC card while no DS is reported (#3154)", () => {
  it("does not promise a BIND9 zone's DS within 30 seconds of signing", async () => {
    dnssecInfo = SIGNED_NO_DS;
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ZoneModal groupId="grp-1" views={[]} zone={ZONE} onClose={() => {}} />
      </QueryClientProvider>,
    );

    // The agent's report has landed: the key is listed, with no DS.
    await screen.findByText("46314");
    const section = screen.getByText(/paste these at the parent registrar/)
      .parentElement as HTMLElement;
    const said = (section.textContent ?? "").replace(/\s+/g, " ");

    expect(said, "the card promises the DS within 30 s").not.toMatch(
      /30\s*s\b/,
    );
    expect(said).toMatch(/BIND9[^.]*about a day after signing/);
    expect(said).toMatch(/PowerDNS[^.]*right after/);
  });
});

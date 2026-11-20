/**
 * @vitest-environment jsdom
 *
 * The DNSSEC card says when a signed zone's DS set changed (#4566).
 *
 * A PowerDNS zone re-created by the reconcile (a lost LMDB volume, a replaced
 * node) is signed again with new keys, so the DS the operator published at the
 * parent no longer matches. The API reports `dnssec_ds_changed_at`; the card
 * has to say so next to the records to publish, and stay quiet for a zone
 * whose DS is its first.
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
      // Edit Zone reads the zone fresh on open (#3269): answer with the row
      // the dialog was opened on.
      listZones: () => Promise.resolve([ZONE]),
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

const DS =
  "1002 13 2 abababababababababababababababababababababababababababababababab";
const INFO: ZoneDnssecInfo = {
  zone_id: "zone-1",
  zone_name: "signed.example.test.",
  dnssec_enabled: true,
  dnssec_policy_id: null,
  dnssec_ds_records: [DS],
  dnssec_synced_at: "2026-11-19T05:51:40Z",
  keys: [],
  dnssec_multi_signer: false,
  signing_servers: 1,
  signing_unmanaged: false,
};

afterEach(() => {
  cleanup();
  dnssecInfo = null;
});

async function dsSection(info: ZoneDnssecInfo): Promise<string> {
  dnssecInfo = info;
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <ZoneModal groupId="grp-1" views={[]} zone={ZONE} onClose={() => {}} />
    </QueryClientProvider>,
  );
  await screen.findByText(DS);
  const section = screen.getByText(/paste these at the parent registrar/)
    .parentElement as HTMLElement;
  return (section.textContent ?? "").replace(/\s+/g, " ");
}

describe("the DNSSEC card when the DS set changed (#4566)", () => {
  it("tells the operator to publish the new DS at the parent", async () => {
    const said = await dsSection({
      ...INFO,
      dnssec_ds_changed_at: "2026-11-19T05:51:40Z",
    });

    expect(said).toMatch(/DS records changed/);
    expect(said).toMatch(/Publish the records below at the parent zone/);
  });

  it("says nothing for a zone still on its first DS", async () => {
    const said = await dsSection({ ...INFO, dnssec_ds_changed_at: null });

    expect(said).not.toMatch(/DS records changed/);
  });
});

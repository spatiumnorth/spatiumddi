/**
 * @vitest-environment jsdom
 *
 * The DNS Pools and DNSSEC Policies pages offer a write only to a user the
 * API will accept (#1879). Every pool write and every DNSSEC-policy write
 * takes a superadmin, so a DNS Editor holding `admin` on the DNS resources
 * is still refused: the controls render disabled with the reason.
 */
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const STAMP = "2026-10-15T00:00:00Z";
const POOL = {
  id: "p1",
  group_id: "g1",
  group_name: "grp",
  zone_id: "z1",
  zone_name: "example.test.",
  name: "web",
  description: "",
  record_name: "www",
  record_type: "A",
  ttl: 30,
  enabled: true,
  hc_type: "tcp",
  hc_target_port: 80,
  hc_interval_seconds: 30,
  next_check_at: null,
  last_checked_at: null,
  member_count: 1,
  healthy_count: 1,
  enabled_count: 1,
  live_count: 1,
  created_at: STAMP,
  modified_at: STAMP,
};
const POLICY = {
  id: "d1",
  name: "custom",
  description: "",
  is_builtin: false,
  algorithm: "ed25519",
  ksk_lifetime_days: 0,
  zsk_lifetime_days: 90,
  nsec3: false,
  nsec3_iterations: 0,
  nsec3_salt_length: 0,
  nsec3_optout: false,
  created_at: STAMP,
  modified_at: STAMP,
};

const myPermissions = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, myPermissions: () => myPermissions() },
    dnsApi: {
      ...actual.dnsApi,
      listAllPools: () => Promise.resolve([POOL]),
      listDnssecPolicies: () => Promise.resolve([POLICY]),
    },
  };
});

import { DNSPoolsPage } from "./DNSPoolsPage";
import { DNSSECPoliciesPage } from "./DNSSECPoliciesPage";

const SUPERADMIN = "Requires superadmin";
// The built-in DNS Editor's grants: every DNS resource, pools read-only.
const DNS_EDITOR = [
  ["admin", "dns_group"],
  ["admin", "dns_zone"],
  ["admin", "dns_record"],
  ["read", "manage_dns_pools"],
];

function signInAs(grants: string[][] | "superadmin") {
  myPermissions.mockResolvedValue(
    grants === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: grants.map(([action, resource_type]) => ({
            action,
            resource_type,
            resource_id: null,
          })),
        },
  );
}

async function show(ui: React.ReactElement, row: RegExp | string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText(row);
  await waitFor(() => expect(myPermissions).toHaveBeenCalled());
  await act(async () => {});
}

const btn = (name: string | RegExp) =>
  screen.getByRole("button", { name }) as HTMLButtonElement;

afterEach(() => {
  cleanup();
  myPermissions.mockReset();
});

describe("#1879 DNS write controls follow the API's superadmin gate", () => {
  const POOL_WRITES = [/New Pool/, "Check now", "Delete pool"];
  const POLICY_WRITES = [/New policy/, "Edit", "Delete"];

  it("refuses a DNS Editor every pool write and says why", async () => {
    signInAs(DNS_EDITOR);
    await show(<DNSPoolsPage />, "web");
    for (const n of POOL_WRITES) {
      expect(btn(n).disabled, String(n)).toBe(true);
      expect(btn(n).title, String(n)).toBe(SUPERADMIN);
    }
  });

  it("offers a superadmin every pool write", async () => {
    signInAs("superadmin");
    await show(<DNSPoolsPage />, "web");
    for (const n of POOL_WRITES) expect(btn(n).disabled, String(n)).toBe(false);
  });

  it("refuses a DNS Editor every DNSSEC-policy write", async () => {
    signInAs(DNS_EDITOR);
    await show(<DNSSECPoliciesPage />, "custom");
    for (const n of POLICY_WRITES) {
      expect(btn(n).disabled, String(n)).toBe(true);
      expect(btn(n).title, String(n)).toBe(SUPERADMIN);
    }
  });

  it("offers a superadmin every DNSSEC-policy write", async () => {
    signInAs("superadmin");
    await show(<DNSSECPoliciesPage />, "custom");
    for (const n of POLICY_WRITES)
      expect(btn(n).disabled, String(n)).toBe(false);
  });
});

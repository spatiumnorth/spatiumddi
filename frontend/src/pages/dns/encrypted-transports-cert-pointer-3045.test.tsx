/**
 * @vitest-environment jsdom
 *
 * The Encrypted transports card names where the certificate lives (#3045).
 * Web UI Certificate is an entry in Appliance -> Fleet's side list, not an
 * Appliance tab, and the card links straight to it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      getOptions: () =>
        Promise.resolve({
          forwarders: [],
          allow_query: [],
          allow_recursion: [],
          allow_transfer: [],
          rrl_exempt_clients: [],
          forward_policy: "first",
          forward_transport: "do53",
          dnssec_validation: "auto",
          recursion_enabled: true,
          dot_port: 853,
          doh_port: 443,
          doq_port: 853,
          doh_path: "/dns-query",
          tls_certificate_id: null,
        }),
      listServers: () => Promise.resolve([]),
    },
    applianceTlsApi: {
      ...actual.applianceTlsApi,
      list: () => Promise.resolve([]),
    },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { OptionsTab } = await import("@/pages/dns/DNSPage");

afterEach(cleanup);

describe("Encrypted transports certificate pointer", () => {
  it("links to the Fleet entry by its real path", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <OptionsTab groupId="grp-1" />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const link = await screen.findByRole("link", {
      name: "Appliance → Fleet → Web UI Certificate",
    });
    expect(link.getAttribute("href")).toBe("/appliance?tab=tls");
  });
});

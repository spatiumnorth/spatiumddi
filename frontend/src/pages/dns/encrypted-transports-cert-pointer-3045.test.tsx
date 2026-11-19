/**
 * @vitest-environment jsdom
 *
 * The Encrypted transports card names where the certificate lives (#3045).
 * Web UI Certificate is an entry in Appliance -> Fleet's side list, not an
 * Appliance tab, and the card links straight to it — on an appliance-hosted
 * control plane, the only place Fleet shows that entry. On Docker / Kubernetes
 * there is no certificate page, so the card names the API instead of linking
 * to a section that would render nothing.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const deployment = vi.hoisted(() => ({ applianceMode: true }));

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
      // The Forwarders card on the same tab; mocked so no request leaves.
      forwarderPresets: () => Promise.resolve({ version: "test", presets: [] }),
    },
    applianceTlsApi: {
      ...actual.applianceTlsApi,
      list: () => Promise.resolve([]),
    },
    versionApi: {
      get: () =>
        Promise.resolve({
          version: "test",
          appliance_mode: deployment.applianceMode,
        }),
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

function renderCard() {
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
}

describe("Encrypted transports certificate pointer", () => {
  beforeEach(() => {
    deployment.applianceMode = true;
  });

  it("links to the Fleet entry by its real path on an appliance", async () => {
    renderCard();
    const link = await screen.findByRole("link", {
      name: "Appliance → Fleet → Web UI Certificate",
    });
    // AppliancePage maps ?tab=tls to Fleet + the web-ui-certificate section.
    expect(link.getAttribute("href")).toBe("/appliance?tab=tls");
  });

  it("links to the Fleet entry by its Docker / Kubernetes name off an appliance", async () => {
    deployment.applianceMode = false;
    renderCard();
    const link = await screen.findByRole("link", {
      name: "Appliance → Fleet → TLS certificates",
    });
    expect(link.getAttribute("href")).toBe("/appliance?tab=tls");
    expect(screen.queryByText(/Web UI Certificate/)).toBeNull();
  });
});

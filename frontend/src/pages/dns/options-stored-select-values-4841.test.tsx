/**
 * @vitest-environment jsdom
 *
 * #4841: the DNS group Options tab shows a stored Notify mode / query log
 * Severity the selects do not list as itself, not as their first choice.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state: { getOptions: () => Promise<unknown> } = {
  getOptions: () => new Promise(() => {}),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      getOptions: () => state.getOptions(),
      listServers: () => Promise.resolve([]),
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

const stored = {
  forwarders: ["192.0.2.53"],
  forward_policy: "first",
  recursion_enabled: false,
  allow_recursion: ["localhost"],
  dnssec_validation: "auto",
  notify_enabled: "yes",
  allow_query: ["any"],
  allow_transfer: ["none"],
  query_log_enabled: false,
  response_log_enabled: false,
  query_log_channel: "file",
  query_log_file: "/var/log/named/queries.log",
  query_log_severity: "info",
  rrl_enabled: false,
  rrl_responses_per_second: 15,
  rrl_window: 15,
  rrl_slip: 2,
  rrl_exempt_clients: [],
  rrl_log_only: false,
  minimal_responses: false,
  dnsdist_enabled: false,
  dnsdist_action: "truncate",
  dnsdist_dynblock_seconds: 60,
  dot_enabled: false,
  dot_port: 853,
  doh_enabled: false,
  doh_port: 443,
  doh_path: "/dns-query",
  forward_transport: "do53",
  forward_tls_verify: true,
  trust_anchors: [],
};

describe("Options tab stored select values (#4841)", () => {
  it("offers the stored notify mode and severity as choices", async () => {
    state.getOptions = () =>
      Promise.resolve({
        ...stored,
        notify_enabled: "primary-only",
        query_log_enabled: true,
        query_log_severity: "debug 3",
      });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <OptionsTab groupId="g-1" />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText(/minimal-responses/);
    const values = () =>
      Array.from(document.querySelectorAll("select")).map((s) => s.value);
    await waitFor(() => expect(values()).toContain("primary-only"));
    expect(values()).toContain("debug 3");
  });
});

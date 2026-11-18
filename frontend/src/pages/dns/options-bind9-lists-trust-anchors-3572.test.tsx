/**
 * @vitest-environment jsdom
 *
 * #3572 — the Options tab shows also-notify, allow-notify, allow-query-cache,
 * blackhole and the trust-anchor editor, which the API already accepted.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state = vi.hoisted(() => ({
  servers: [{ driver: "bind9" }] as { driver: string }[],
  anchors: [] as unknown[],
  blackhole: [] as string[],
  update: vi.fn(),
  add: vi.fn(),
  del: vi.fn(),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      getOptions: () =>
        Promise.resolve({
          forwarders: [],
          allow_query: ["any"],
          allow_recursion: [],
          allow_transfer: ["none"],
          also_notify: ["192.0.2.10"],
          allow_notify: [],
          allow_query_cache: ["localhost", "localnets"],
          blackhole: state.blackhole,
          rrl_exempt_clients: [],
          forward_policy: "first",
          forward_transport: "do53",
          dnssec_validation: "auto",
          trust_anchors: state.anchors,
          recursion_enabled: true,
          dot_port: 853,
          doh_port: 443,
          doq_port: 853,
          doh_path: "/dns-query",
          tls_certificate_id: null,
        }),
      updateOptions: (_g: string, d: unknown) => {
        state.update(d);
        return Promise.resolve({});
      },
      addTrustAnchor: (_g: string, d: unknown) => {
        state.add(d);
        return Promise.resolve({});
      },
      deleteTrustAnchor: (_g: string, id: string) => {
        state.del(id);
        return Promise.resolve({});
      },
      listServers: () => Promise.resolve(state.servers),
      forwarderPresets: () => Promise.resolve({ version: "test", presets: [] }),
    },
    applianceTlsApi: {
      ...actual.applianceTlsApi,
      list: () => Promise.resolve([]),
    },
    versionApi: {
      get: () => Promise.resolve({ version: "test", appliance_mode: true }),
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

afterEach(() => {
  cleanup();
  state.servers = [{ driver: "bind9" }];
  state.anchors = [];
  state.blackhole = [];
  vi.clearAllMocks();
});

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <OptionsTab groupId="grp-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe(
  "Options tab BIND9 lists and trust anchors (#3572)",
  { timeout: 30000 },
  () => {
    it("fills the lists and sends only the changed one on save", async () => {
      renderTab();
      const also = (await screen.findByPlaceholderText(
        /192\.0\.2\.10, 192\.0\.2\.11/,
      )) as HTMLInputElement;
      expect(also.value).toBe("192.0.2.10");
      const bh = screen.getByLabelText(/^blackhole/) as HTMLInputElement;
      fireEvent.change(bh, {
        target: { value: "203.0.113.0/24, 198.51.100.7" },
      });
      fireEvent.click(screen.getByRole("button", { name: /Save Changes/ }));
      await waitFor(() => expect(state.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(state.update).toHaveBeenCalledWith({
        blackhole: ["203.0.113.0/24", "198.51.100.7"],
      });
    });

    it("disables blackhole and allow-query-cache on a PowerDNS group", async () => {
      state.servers = [{ driver: "powerdns" }];
      renderTab();
      const bh = (await screen.findByLabelText(
        /^blackhole/,
      )) as HTMLInputElement;
      expect(bh.disabled).toBe(true);
      expect(bh.title).toMatch(/PowerDNS/);
      expect(
        (screen.getByLabelText(/^allow-query-cache/) as HTMLInputElement)
          .disabled,
      ).toBe(true);
    });

    it("keeps a stored blackhole editable on a PowerDNS group so it can be cleared", async () => {
      state.servers = [{ driver: "powerdns" }];
      state.blackhole = ["203.0.113.0/24"];
      renderTab();
      const bh = (await screen.findByLabelText(
        /^blackhole/,
      )) as HTMLInputElement;
      expect(bh.disabled).toBe(false);
    });

    it("adds a trust anchor through the API after a local check", async () => {
      renderTab();
      const add = await screen.findByRole("button", {
        name: /Add trust anchor/,
      });
      fireEvent.click(add);
      expect(await screen.findByText(/Key tag must be/)).toBeTruthy();
      expect(state.add).not.toHaveBeenCalled();
      fireEvent.change(screen.getByLabelText("Key tag"), {
        target: { value: "20326" },
      });
      fireEvent.change(screen.getByLabelText(/^Public key/), {
        target: { value: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJz" },
      });
      fireEvent.click(add);
      await waitFor(() => expect(state.add).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(state.add).toHaveBeenCalledWith({
        zone_name: ".",
        algorithm: 8,
        key_tag: 20326,
        public_key: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJz",
        is_initial_key: true,
      });
    });

    it("lists and deletes an existing anchor; no add form on a PowerDNS group", async () => {
      state.anchors = [
        {
          id: "a1",
          zone_name: ".",
          algorithm: 8,
          key_tag: 20326,
          public_key: "AAAA",
          is_initial_key: true,
          added_at: "2026-01-01T00:00:00Z",
        },
      ];
      renderTab();
      fireEvent.click(
        await screen.findByRole("button", { name: /Delete trust anchor/ }),
      );
      await waitFor(() => expect(state.del).toHaveBeenCalledWith("a1"), {
        timeout: 10000,
      });
      cleanup();
      state.servers = [{ driver: "powerdns" }];
      renderTab();
      expect(
        await screen.findByText(/Only BIND9 applies trust anchors/),
      ).toBeTruthy();
      expect(
        screen.queryByRole("button", { name: /Add trust anchor/ }),
      ).toBeNull();
    });
  },
);

/**
 * @vitest-environment jsdom
 *
 * BIND 9.20 will not load ``dnssec-validation yes`` without a trust anchor,
 * and the API now refuses it (#3560). The Options tab must say so before
 * Save instead of offering a value that comes back as a 422: ``yes`` is
 * disabled with the reason until the group has an anchor. A group stored at
 * ``yes`` before the refusal keeps the option (it can still be re-saved) and
 * shows the server's warning that it is rendered as ``auto``.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state = vi.hoisted(() => ({
  validation: "auto",
  anchors: [] as unknown[],
  servers: [] as { driver: string }[],
  warnings: [] as string[],
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
          allow_query: [],
          allow_recursion: [],
          allow_transfer: [],
          rrl_exempt_clients: [],
          forward_policy: "first",
          forward_transport: "do53",
          dnssec_validation: state.validation,
          trust_anchors: state.anchors,
          dnssec_warnings: state.warnings,
          recursion_enabled: true,
          dot_port: 853,
          doh_port: 443,
          doq_port: 853,
          doh_path: "/dns-query",
          tls_certificate_id: null,
        }),
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
  state.validation = "auto";
  state.anchors = [];
  state.servers = [];
  state.warnings = [];
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

async function yesOption(): Promise<HTMLOptionElement> {
  const auto = await screen.findByRole("option", { name: /^auto — validate/ });
  return auto.parentElement!.querySelector(
    'option[value="yes"]',
  ) as HTMLOptionElement;
}

describe("dnssec_validation yes needs a trust anchor (#3560)", () => {
  it("disables yes with the reason on a BIND9 group with no anchor", async () => {
    state.servers = [{ driver: "bind9" }];
    renderTab();
    expect((await yesOption()).disabled).toBe(true);
    expect(await screen.findByText(/needs a trust anchor first/)).toBeTruthy();
  });

  it("explains that a root anchor must be initial-key (#3609)", async () => {
    state.servers = [{ driver: "bind9" }];
    renderTab();
    const hint = await screen.findByText(/needs a trust anchor first/);
    expect(hint.textContent).toMatch(
      /root \("\."\) anchor must be initial-key/,
    );
    expect(hint.textContent).toMatch(/static root anchor is refused/);
  });

  it("shows the server's warning for a stored static root anchor (#3609)", async () => {
    state.servers = [{ driver: "bind9" }];
    state.anchors = [{ id: "a1", zone_name: ".", is_initial_key: false }];
    state.warnings = [
      "The root ('.') trust anchor is stored as static, which BIND refuses beside 'auto' and which fails at the next root key rollover in any mode, so it is rendered as initial-key (RFC 5011).",
    ];
    renderTab();
    expect(await screen.findByText(/rendered as initial-key/)).toBeTruthy();
  });

  it("treats an empty group as BIND9", async () => {
    renderTab();
    expect((await yesOption()).disabled).toBe(true);
  });

  it("offers yes once the group has an anchor", async () => {
    state.servers = [{ driver: "bind9" }];
    state.anchors = [{ id: "a1" }];
    renderTab();
    const yes = await yesOption();
    // listServers resolves after getOptions; wait for the settled render.
    await screen.findByRole("option", { name: /^no — do not validate/ });
    expect(yes.disabled).toBe(false);
    expect(screen.queryByText(/needs a trust anchor first/)).toBeNull();
  });

  it("leaves yes alone on a Technitium group", async () => {
    state.servers = [{ driver: "technitium" }];
    renderTab();
    await screen.findByRole("option", { name: /^auto — validate/ });
    // Wait for the servers query to settle before reading the option.
    await vi.waitFor(async () =>
      expect((await yesOption()).disabled).toBe(false),
    );
  });

  it("keeps a stored yes selectable and shows the rendered-as-auto warning", async () => {
    state.servers = [{ driver: "bind9" }];
    state.validation = "yes";
    state.warnings = [
      "dnssec_validation is 'yes' but no trust anchor is configured: BIND 9.20 refuses that config, so it is rendered as 'auto'",
    ];
    renderTab();
    expect((await yesOption()).disabled).toBe(false);
    expect(await screen.findByText(/rendered as 'auto'/)).toBeTruthy();
  });
});

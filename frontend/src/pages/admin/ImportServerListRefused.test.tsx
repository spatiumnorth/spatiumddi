/**
 * @vitest-environment jsdom
 *
 * A refused server list is said as refused, never as "no eligible servers"
 * (#2524). The Windows DNS, Cloud and Windows DHCP importers read a
 * superadmin-only list of servers as the tab opens; a Viewer's 403 used to
 * leave the picker saying the appliance had none.
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const refused = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "Superadmin required" } },
  });
const winDns = vi.fn();
const cloudDns = vi.fn();
const winDhcp = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "authApi" && method === "myPermissions")
                return () =>
                  Promise.resolve({
                    is_superadmin: false,
                    grants: [
                      { action: "read", resource_type: "*", resource_id: null },
                    ],
                  });
              if (name === "dnsImportApi" && method === "windowsDNSServers")
                return () => winDns();
              if (name === "dnsImportApi" && method === "cloudDNSServers")
                return () => cloudDns();
              if (name === "dhcpImportApi" && method === "windowsServers")
                return () => winDhcp();
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

import { DNSImportPage } from "./DNSImportPage";
import { DHCPImportPage } from "./DHCPImportPage";

async function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {});
  await act(async () => {});
}

async function openTab(name: RegExp) {
  fireEvent.click(screen.getByRole("button", { name }));
  await act(async () => {});
  await act(async () => {});
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("importer server pickers over a refused list", () => {
  it.each([
    ["Windows DNS", winDns, DNSImportPage, /^Windows DNS/],
    ["Cloud", cloudDns, DNSImportPage, /^Cloud/],
    ["Windows DHCP", winDhcp, DHCPImportPage, /^Windows DHCP/],
  ] as const)("%s says the read was refused", async (_n, fn, Page, tab) => {
    fn.mockReset();
    fn.mockImplementation(refused);
    await show(<Page />);
    await openTab(tab);
    expect(
      await screen.findByText(
        /You don't have permission to see the servers to import from/,
      ),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain("no eligible servers");
  });

  it("still says no eligible servers over a genuinely empty list", async () => {
    winDns.mockReset();
    winDns.mockResolvedValue([]);
    await show(<DNSImportPage />);
    await openTab(/^Windows DNS/);
    expect(await screen.findByText(/no eligible servers/)).toBeTruthy();
  });
});

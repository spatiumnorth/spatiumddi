/**
 * @vitest-environment jsdom
 *
 * The DNS and DHCP server detail modals offer Pause / Resume only to a user
 * the API will accept (#2076). Both routes take a superadmin whatever the
 * caller's grants, so anyone else sees the control disabled with the reason,
 * exactly as the server rows show it.
 */
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const myPermissions = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, myPermissions: () => myPermissions() },
  };
});

import { ServerDetailModal as DnsModal } from "./dns/ServerDetailModal";
import { ServerDetailModal as DhcpModal } from "./dhcp/ServerDetailModal";

const SUPERADMIN = "Requires superadmin";

function server(maintenance_mode: boolean) {
  return {
    id: "s1",
    group_id: "g1",
    server_group_id: "g1",
    name: "ns1",
    driver: "bind9",
    roles: [],
    host: "10.0.0.1",
    port: 53,
    is_enabled: true,
    is_primary: false,
    maintenance_mode,
    maintenance_reason: null,
    maintenance_started_at: null,
  } as never;
}

function signInAs(superadmin: boolean) {
  myPermissions.mockResolvedValue({
    is_superadmin: superadmin,
    grants: superadmin
      ? []
      : [
          { action: "admin", resource_type: "dns_group", resource_id: null },
          { action: "admin", resource_type: "dhcp_server", resource_id: null },
        ],
  });
}

async function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(myPermissions).toHaveBeenCalled());
  await act(async () => {});
}

const btn = (name: string) =>
  screen.getByRole("button", { name }) as HTMLButtonElement;

afterEach(() => {
  cleanup();
  myPermissions.mockReset();
});

const MODALS = [
  ["DNS", (m: boolean) => <DnsModal server={server(m)} onClose={() => {}} />],
  ["DHCP", (m: boolean) => <DhcpModal server={server(m)} onClose={() => {}} />],
] as const;

describe.each(MODALS)("#2076 %s server detail modal", (_n, make) => {
  it.each([
    ["Pause", false],
    ["Resume", true],
  ])("refuses a non-superadmin %s and says why", async (label, paused) => {
    signInAs(false);
    await show(make(paused));
    expect(btn(label).disabled).toBe(true);
    expect(btn(label).title).toBe(SUPERADMIN);
  });

  it.each([
    ["Pause", false],
    ["Resume", true],
  ])("offers a superadmin %s", async (label, paused) => {
    signInAs(true);
    await show(make(paused));
    // The grant arrives asynchronously; until it does the gate denies.
    await waitFor(() => expect(btn(label).disabled).toBe(false));
  });
});

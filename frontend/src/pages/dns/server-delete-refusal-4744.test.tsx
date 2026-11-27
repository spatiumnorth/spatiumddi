/**
 * @vitest-environment jsdom
 *
 * #4744 — a refused "Delete DNS Server" says why inside its confirm (an
 * announced alert) instead of staying open, unchanged and silent.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DNSServerGroup } from "@/lib/api";

const deleteServer = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    dnsApi: {
      ...actual.dnsApi,
      listServers: () =>
        Promise.resolve([
          {
            id: "s1",
            group_id: "g1",
            name: "ns1",
            driver: "bind9",
            roles: [],
            host: "192.0.2.53",
            port: 53,
            is_primary: true,
            is_enabled: false,
            status: "unknown",
            removing: false,
          },
        ]),
      listZones: () => Promise.resolve([]),
      deleteServer: (...a: unknown[]) => deleteServer(...a),
    },
  };
});

import { ServersTab } from "./DNSPage";

afterEach(() => {
  cleanup();
  deleteServer.mockReset();
});

describe("Delete DNS Server refusal (#4744)", () => {
  it("shows the server's reason in an alert and keeps the confirm open", async () => {
    deleteServer.mockRejectedValue({
      response: { status: 404, data: { detail: "Server not found" } },
    });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ServersTab group={{ id: "g1" } as DNSServerGroup} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await screen.findByText("ns1");
    await user.click(screen.getByRole("button", { name: "Delete server" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    const alert = await waitFor(() => screen.getByRole("alert"));
    expect(alert.textContent).toContain("Server not found");
    expect(screen.getByRole("button", { name: "Delete" })).toBeTruthy();
  });
});

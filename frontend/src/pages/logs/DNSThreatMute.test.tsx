/**
 * @vitest-environment jsdom
 *
 * Mute / Unmute are offered only to a caller the server accepts (write on
 * servers), and a refused mute says why in the server's words (#2531).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

type Grants = { is_superadmin: boolean; grants: Record<string, unknown>[] };
const perms: { value: Grants } = {
  value: { is_superadmin: false, grants: [] },
};
const muteCalls = vi.fn();

const win = {
  id: "w1",
  client_ip: "192.0.2.99",
  window_start: "2026-10-22T10:00:00Z",
  window_end: "2026-10-22T11:00:00Z",
  query_count: 100,
  distinct_qnames: 90,
  distinct_parents: 1,
  top_parent: "evil.example",
  top_parent_subdomains: 90,
  max_label_length: 50,
  mean_label_entropy: 4,
  payload_qtype_count: 1,
  tunnel_score: 90,
  tunnel_signals: [],
  beacon_score: 0,
  beacon_candidates: [],
  beacon_detail: "",
  dga_score: 0,
  dga_candidates: [],
  dga_signals: [],
  dga_detail: "",
  allowlisted: false,
  server_count: 1,
  muted: false,
  mute_reason: null,
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: async () => ({ is_superadmin: perms.value.is_superadmin }),
      myPermissions: async () => perms.value,
    },
    dnsThreatApi: {
      listWindows: async () => [win],
      summary: async () => ({}),
      listMutes: async () => [
        {
          id: "m1",
          client_ip: "192.0.2.7",
          reason: "scanner",
          muted_until: null,
          active: true,
          muted_by_display: "admin",
        },
      ],
      mute: (b: unknown) => muteCalls(b),
      unmute: async () => undefined,
    },
  };
});

import { DNSThreatTab } from "./DNSThreatTab";

function renderTab() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <DNSThreatTab />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("DNS Threat mute controls (#2531)", () => {
  it("disables Mute for a Viewer, with the reason", async () => {
    perms.value = {
      is_superadmin: false,
      grants: [{ action: "read", resource_type: "*", resource_id: null }],
    };
    renderTab();
    const mute = (await screen.findByRole("button", {
      name: "Mute",
    })) as HTMLButtonElement;
    await vi.waitFor(() => expect(mute.disabled).toBe(true));
    expect(mute.title).toContain("write permission on servers");
  });

  it("offers Mute to a caller with write on servers", async () => {
    perms.value = {
      is_superadmin: false,
      grants: [{ action: "write", resource_type: "server", resource_id: null }],
    };
    renderTab();
    const mute = (await screen.findByRole("button", {
      name: "Mute",
    })) as HTMLButtonElement;
    await vi.waitFor(() => expect(mute.disabled).toBe(false));
  });

  it("shows the server's reason when a mute is refused", async () => {
    perms.value = { is_superadmin: true, grants: [] };
    muteCalls.mockRejectedValue({
      message: "Request failed with status code 403",
      response: {
        status: 403,
        data: { detail: "Permission denied: need 'write' on 'server'" },
      },
    });
    renderTab();
    const mute = await screen.findByRole("button", { name: "Mute" });
    await vi.waitFor(() =>
      expect((mute as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(mute);
    fireEvent.change(await screen.findByRole("textbox"), {
      target: { value: "known scanner" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mute client" }));
    await screen.findByText("Permission denied: need 'write' on 'server'");
    expect(document.body.textContent).not.toContain("status code 403");
  });
});

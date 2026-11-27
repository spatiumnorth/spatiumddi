/**
 * @vitest-environment jsdom
 *
 * The firewall feed Edit dialog reads the feed when it opens and sends only
 * the fields the operator changed (#4777), so `enabled` another admin cleared
 * is not set again by an edit of the name.
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

const h = vi.hoisted(() => ({ reads: 0, update: vi.fn() }));
const base = {
  id: "f1",
  name: "Feed",
  description: "old description",
  enabled: true,
  kind: "ip",
  poll_path: "/p/x",
  last_polled_at: null,
  last_polled_ip: null,
  poll_count: 0,
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
};
const stored = { ...base, description: "changed elsewhere", enabled: false };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    firewallFeedsApi: {
      ...actual.firewallFeedsApi,
      list: async () => {
        h.reads += 1;
        return [h.reads === 1 ? base : stored];
      },
      update: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(stored);
      },
    },
  };
});

import { FirewallFeedsPage } from "./FirewallFeedsPage";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

describe("Firewall feed Edit reads the row when it opens (#4777)", () => {
  it("shows what another client stored and Save sends only the name", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <FirewallFeedsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle(/edit/i));
    expect(await screen.findByDisplayValue("changed elsewhere")).toBeTruthy();
    fireEvent.change(screen.getByDisplayValue("Feed"), {
      target: { value: "Renamed" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(h.update).toHaveBeenCalled());
    expect(h.update).toHaveBeenCalledWith("f1", { name: "Renamed" });
  });
});

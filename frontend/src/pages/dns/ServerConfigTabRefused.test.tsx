/**
 * @vitest-environment jsdom
 *
 * A DNS server's Config tab follows the superadmin-only rendered-config read
 * (#2530, #869). It is kept from a user the API refuses; should the read be
 * refused anyway it says so in words (not "Failed to load — try again") and
 * is not asked again.
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const myPermissions = vi.fn();
const rendered = vi.fn();

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
                return () => myPermissions();
              if (name === "dnsApi" && method === "getServerRenderedConfig")
                return () => rendered();
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

import { ServerDetailModal } from "./ServerDetailModal";
import type { DNSServer } from "@/lib/api";

const SERVER = {
  id: "s1",
  group_id: "g1",
  name: "ns1",
  driver: "bind9",
  roles: [],
  host: "192.0.2.53",
  port: 53,
  is_primary: true,
  is_enabled: true,
  status: "active",
} as unknown as DNSServer;

beforeEach(() => {
  vi.useFakeTimers();
  rendered.mockReset();
  rendered.mockImplementation(() =>
    Promise.reject({
      response: { status: 403, data: { detail: "Superadmin required" } },
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  myPermissions.mockReset();
});

async function show(superadmin: boolean) {
  myPermissions.mockResolvedValue(
    superadmin
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: [{ action: "read", resource_type: "*", resource_id: null }],
        },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ServerDetailModal server={SERVER} onClose={() => {}} />
    </QueryClientProvider>,
  );
  await act(async () => {
    await vi.advanceTimersByTimeAsync(50);
  });
}

describe("DNS server Config tab", () => {
  it("is not offered to a Viewer, and its read is never made", async () => {
    await show(false);
    expect(screen.queryByRole("button", { name: /^Config/ })).toBeNull();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(61_000);
    });
    expect(rendered).not.toHaveBeenCalled();
  });

  it("says a refused read was refused and does not ask again", async () => {
    await show(true);
    fireEvent.click(screen.getByRole("button", { name: /^Config/ }));
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(61_000);
    });
    expect(rendered).toHaveBeenCalledTimes(1);
    const text = document.body.textContent ?? "";
    expect(text).toContain("You don't have permission to see the rendered");
    expect(text).not.toContain("Failed to load");
  });
});

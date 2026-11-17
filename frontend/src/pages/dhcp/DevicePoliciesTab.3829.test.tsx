/**
 * @vitest-environment jsdom
 *
 * A failed policies read is not drawn as a group with no policies (#3829).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

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
                return async () => ({ is_superadmin: true, grants: [] });
              if (name === "dhcpApi" && method === "listDevicePolicies")
                return async () => {
                  throw new Error("boom");
                };
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { DevicePoliciesTab } = await import("./DevicePoliciesTab");

afterEach(cleanup);

describe("DevicePoliciesTab failed read (#3829)", () => {
  it("says it could not load, not that there are no policies", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <DevicePoliciesTab groupId="g1" />
      </QueryClientProvider>,
    );
    expect(
      await screen.findByText(/Couldn't load device policies/),
    ).toBeTruthy();
    expect(screen.queryByText(/No device policies yet/)).toBeNull();
  });
});

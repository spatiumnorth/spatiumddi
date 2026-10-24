/**
 * @vitest-environment jsdom
 *
 * The IP detail's Reputation "Check now" is offered only to a user the API
 * will accept (#1879's sweep). `POST /dnsbl/check` is behind the DNSBL
 * router's method gate, so it takes write on `dnsbl`, not write on the
 * address: an IPAM Editor can edit the address and is still refused the
 * check.
 */
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const myPermissions = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, myPermissions: () => myPermissions() },
    // Pending: `enabled()` reads every module as on while loading.
    featureModulesApi: {
      ...actual.featureModulesApi,
      list: () => new Promise(() => {}),
    },
    dnsblApi: {
      ...actual.dnsblApi,
      byIp: () =>
        Promise.resolve({ ip: "192.0.2.10", listed_count: 0, entries: [] }),
    },
  };
});

import { ReputationSection } from "./IPDetailModal";

function signInAs(grants: string[][] | "superadmin") {
  myPermissions.mockResolvedValue(
    grants === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: grants.map(([action, resource_type]) => ({
            action,
            resource_type,
            resource_id: null,
          })),
        },
  );
}

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ReputationSection address="192.0.2.10/32" />
    </QueryClientProvider>,
  );
  // The section body depends on read access; the button does not.
  await screen.findByRole("button", { name: /Check now/ });
  await waitFor(() => expect(myPermissions).toHaveBeenCalled());
  await act(async () => {});
  return screen.getByRole("button", { name: /Check now/ }) as HTMLButtonElement;
}

afterEach(() => {
  cleanup();
  myPermissions.mockReset();
});

describe("Reputation Check now follows the DNSBL router's write gate", () => {
  it("refuses an IPAM Editor, who may edit the address but not DNSBL", async () => {
    signInAs([
      ["admin", "ip_space"],
      ["admin", "ip_block"],
      ["admin", "subnet"],
      ["admin", "ip_address"],
    ]);
    const b = await show();
    expect(b.disabled).toBe(true);
    expect(b.title).toBe("Requires write permission on DNSBL");
  });

  it("offers it to a user holding write on dnsbl", async () => {
    signInAs([["write", "dnsbl"]]);
    const b = await show();
    expect(b.disabled).toBe(false);
  });

  it("offers it to a superadmin", async () => {
    signInAs("superadmin");
    const b = await show();
    expect(b.disabled).toBe(false);
  });
});

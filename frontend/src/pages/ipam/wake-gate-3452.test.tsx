/**
 * @vitest-environment jsdom
 *
 * Wake was offered enabled to users the route refuses (#3452): it needs read
 * on 'use_network_tools' and write on the address's subnet.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

let nmapModuleOn = true;
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => (id === "tools.nmap" ? nmapModuleOn : true),
  }),
}));

const { IPDetailModal } = await import("./IPDetailModal");

afterEach(() => {
  cleanup();
  nmapModuleOn = true;
  for (const name of Object.keys(answers)) delete answers[name];
});

function signInAs(grants: [string, string, string?][]) {
  const myPermissions = vi.fn(() =>
    Promise.resolve({
      is_superadmin: false,
      grants: grants.map(([action, resource_type, resource_id]) => ({
        action,
        resource_type,
        resource_id: resource_id ?? null,
      })),
    }),
  );
  answers.authApi = { myPermissions };
  return myPermissions;
}

const STAMP = "2026-10-22T00:00:00Z";
const ADDR = {
  id: "a1",
  subnet_id: "s1",
  address: "10.71.1.10",
  status: "allocated",
  role: null,
  hostname: "h",
  fqdn: null,
  description: "",
  mac_address: "aa:bb:cc:dd:ee:ff",
  tags: {},
  custom_fields: {},
  last_profile_scan_id: null,
  last_profiled_at: STAMP,
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as IPAddress;

function openDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <IPDetailModal
          address={ADDR}
          canEdit={true}
          onClose={() => {}}
          onEdit={() => {}}
          onScan={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const wakeButton = () =>
  Array.from(document.querySelectorAll("button")).find(
    (b) => b.textContent?.trim() === "Wake",
  ) as HTMLButtonElement;

async function opened() {
  openDetail();
  await waitFor(() => expect(wakeButton()).toBeTruthy());
  await new Promise((r) => setTimeout(r, 50));
}

describe("Wake-on-LAN gate", () => {
  it("is disabled with the reason for the built-in editors", async () => {
    signInAs([
      ["read", "ip_address"],
      ["write", "subnet"],
    ]);
    await opened();
    expect(wakeButton().disabled).toBe(true);
    expect(wakeButton().title).toBe(
      "Requires read on network tools and write on subnets",
    );
  });

  it("is disabled for a read-only viewer", async () => {
    signInAs([["read", "*"]]);
    await opened();
    expect(wakeButton().disabled).toBe(true);
  });

  it("is offered with both grants", async () => {
    signInAs([
      ["read", "use_network_tools"],
      ["write", "subnet"],
    ]);
    await opened();
    expect(wakeButton().disabled).toBe(false);
  });

  it("is disabled for a write grant scoped to this subnet only", async () => {
    // The route's IPAM gate checks write on subnets type-wide; a grant scoped
    // to the address's own subnet is refused there (403), so Wake must not
    // be offered on it.
    signInAs([
      ["read", "use_network_tools"],
      ["write", "subnet", "s1"],
    ]);
    await opened();
    expect(wakeButton().disabled).toBe(true);
  });
});

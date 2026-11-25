/**
 * @vitest-environment jsdom
 *
 * #3361: the IP detail carries the padlock and Lock / Unlock behind the
 * `lock` grant, disables Delete on a locked address with the reason in its
 * title, and says on Edit what an edit lock freezes. A dynamic-lease mirror
 * takes no Lock action.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
let granted = new Set<string>();

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
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: (action: string, resource: string) =>
        granted.has(`${action}:${resource}`),
    }),
  };
});

const { IPDetailModal } = await import("./IPDetailModal");
afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-11-14T00:00:00Z";
function addr(extra: Partial<IPAddress>): IPAddress {
  return {
    id: "a1",
    subnet_id: "s1",
    address: "10.71.1.10",
    status: "allocated",
    role: null,
    hostname: "h",
    fqdn: null,
    description: "",
    mac_address: null,
    tags: {},
    custom_fields: {},
    created_at: STAMP,
    modified_at: STAMP,
    ...extra,
  } as unknown as IPAddress;
}

function open(a: IPAddress) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <IPDetailModal
          address={a}
          canEdit={true}
          onClose={() => {}}
          onEdit={() => {}}
          onScan={() => {}}
          onDelete={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("IP detail locks (#3361)", () => {
  it("a locked address: padlock, Unlock, Delete disabled with the reason, Edit hint", () => {
    granted = new Set(["lock:ip_address"]);
    open(
      addr({
        lock_level: "edit",
        locked_by: "alice",
        lock_reason: "PCI freeze",
      }),
    );
    expect(screen.getByTestId("lock-badge").getAttribute("title")).toContain(
      "PCI freeze",
    );
    expect(screen.getByRole("button", { name: "Unlock" })).toBeTruthy();
    const del = screen.getByRole("button", {
      name: /Delete/,
    }) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
    expect(del.title).toContain("alice");
    const edit = screen.getByRole("button", {
      name: /Edit/,
    }) as HTMLButtonElement;
    expect(edit.disabled).toBe(false);
    expect(edit.title).toContain("description");
  });

  it("an unlocked address offers Lock to a holder of the grant and Delete stays on", () => {
    granted = new Set(["lock:ip_address"]);
    open(addr({}));
    expect(screen.getByRole("button", { name: "Lock" })).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /Delete/ }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(screen.queryByTestId("lock-badge")).toBeNull();
  });

  it("no Lock without the grant, and none on a dynamic-lease mirror", () => {
    granted = new Set();
    open(addr({}));
    expect(screen.queryByRole("button", { name: "Lock" })).toBeNull();
    cleanup();
    granted = new Set(["lock:ip_address"]);
    open(addr({ auto_from_lease: true }));
    expect(screen.queryByRole("button", { name: "Lock" })).toBeNull();
  });
});

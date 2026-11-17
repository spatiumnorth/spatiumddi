/**
 * @vitest-environment jsdom
 *
 * The subnet page's Address Sets tab for a holder whose grant names the subnet:
 * Edit and Delete follow what the handlers admit, admin on the set (#4184).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}
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
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function grants(list: Array<[string, string, string | null]>) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({
      is_superadmin: false,
      grants: list.map(([action, resource_type, resource_id]) => ({
        action,
        resource_type,
        resource_id,
      })),
    }),
  );
}

const { AddressSetsSubnetPanel } = await import("./IPAMPage");

const subnet = { id: "sub-1", space_id: "sp-1", block_id: "b-1" } as never;
const SET = {
  id: "set-1",
  subnet_id: "sub-1",
  name: "cams",
  description: "",
  range_kind: "cidr",
  cidr: "10.0.0.0/28",
  customer_id: null,
  site_id: null,
};

describe("Address Sets tab for a subnet-scoped writer", () => {
  it("withholds Edit and Delete from a subnet writer (#4184)", async () => {
    grants([
      ["read", "address_set", null],
      ["write", "subnet", "sub-1"],
    ]);
    answer("addressSetsApi", "list", () => Promise.resolve([SET]));
    open(<AddressSetsSubnetPanel subnet={subnet} />);
    await screen.findByText("cams");
    await waitFor(() =>
      expect(screen.queryByText("Loading address sets…")).toBeNull(),
    );
    expect(screen.queryByTitle("Edit address set")).toBeNull();
    expect(screen.queryByTitle("Delete address set")).toBeNull();
  });

  it("still offers them to admin on the set (#4184)", async () => {
    grants([
      ["read", "address_set", null],
      ["admin", "address_set", "set-1"],
    ]);
    answer("addressSetsApi", "list", () => Promise.resolve([SET]));
    open(<AddressSetsSubnetPanel subnet={subnet} />);
    expect(await screen.findByTitle("Edit address set")).toBeTruthy();
    expect(screen.getByTitle("Delete address set")).toBeTruthy();
  });
});

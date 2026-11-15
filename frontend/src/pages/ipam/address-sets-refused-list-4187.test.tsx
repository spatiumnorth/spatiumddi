/**
 * @vitest-environment jsdom
 *
 * The subnet page's Address Sets tab over a list refused to the reader says so,
 * and invites no one who cannot create to create one (#4187).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}
const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      isAxiosError: true,
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

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
describe("Address Sets tab over a refused list", () => {
  it("says a refused list was refused, not that it is empty (#4187)", async () => {
    grants([["write", "subnet", "sub-1"]]);
    answer("addressSetsApi", "list", refused);
    open(<AddressSetsSubnetPanel subnet={subnet} />);
    expect(
      await screen.findByText(/Permission denied|permission/i),
    ).toBeTruthy();
    expect(screen.queryByText("No address sets in this subnet.")).toBeNull();
    expect(screen.queryByText(/Create one to delegate/)).toBeNull();
  });

  it("does not invite a reader who cannot create to create (#4187)", async () => {
    grants([["read", "address_set", null]]);
    answer("addressSetsApi", "list", () => Promise.resolve([]));
    open(<AddressSetsSubnetPanel subnet={subnet} />);
    expect(
      await screen.findByText("No address sets in this subnet."),
    ).toBeTruthy();
    expect(screen.queryByText(/Create one to delegate/)).toBeNull();
  });
});

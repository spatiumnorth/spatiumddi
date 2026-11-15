/**
 * @vitest-environment jsdom
 *
 * IPAM: Allocate IP never offers the address its last open allocated (#3866).
 * The API objects are replaced by recorders; the permission hook is real,
 * fed by ``authApi.myPermissions``.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
/** Every ``<api>.<method>`` call made, in order. */
const calls: string[] = [];

const mods = { ready: true, off: new Set<string>() };

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
                : (...args: unknown[]) => {
                    calls.push(`${name}.${method}`);
                    return (answers[name]?.[method] ?? pending)(...args);
                  },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: mods.ready,
    isLoading: !mods.ready,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !mods.off.has(id),
  }),
}));

const { AddAddressModal } = await import("./ipam/IPAMPage");

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

beforeEach(() => {
  mods.ready = true;
  mods.off = new Set();
  calls.length = 0;
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode, qc?: QueryClient) {
  const client =
    qc ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const r = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...r };
}

describe("Allocate IP preview (#3866)", () => {
  it("does not offer the previous open's address while the re-read is pending", async () => {
    answer("ipamApi", "previewNextIp", () =>
      Promise.resolve({ address: "10.85.20.7", strategy: "sequential" }),
    );
    const first = open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />);
    expect(await screen.findByText("10.85.20.7")).toBeTruthy();
    first.unmount();
    // Let the cache's garbage-collection timer run, as the seconds between
    // two real opens do.
    await new Promise((r) => setTimeout(r, 20));

    answer("ipamApi", "previewNextIp", () => new Promise(() => {}));
    open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />, first.client);
    await screen.findByText("Hostname *");
    expect(screen.queryByText("10.85.20.7")).toBeNull();
  });
});

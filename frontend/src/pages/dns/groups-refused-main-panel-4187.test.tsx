/**
 * @vitest-environment jsdom
 *
 * The DNS page with nothing selected, for a user refused the server group
 * list: the main panel said "Create a server group to start managing DNS."
 * beside a sidebar saying the list was refused (#4187). It says the refusal;
 * and a user who cannot create a group is not told to.
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

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => false,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { DNSPage } = await import("./DNSPage");

describe("DNS page main panel over a refused group list (#4187)", () => {
  it("does not say to create a group", async () => {
    answer("dnsApi", "listGroups", refused);
    open(<DNSPage />);
    await waitFor(() =>
      expect(screen.getAllByText(/permission/i).length).toBeGreaterThan(1),
    );
    expect(screen.queryByText(/Create a server group to start/)).toBeNull();
  });

  it("an empty list for a non-superadmin is not an invitation", async () => {
    answer("dnsApi", "listGroups", () => Promise.resolve([]));
    open(<DNSPage />);
    expect(await screen.findByText("No DNS server groups yet.")).toBeTruthy();
    expect(screen.queryByText(/Create a server group to start/)).toBeNull();
  });
});

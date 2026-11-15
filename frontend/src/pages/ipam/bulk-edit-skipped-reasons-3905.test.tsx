/**
 * @vitest-environment jsdom
 *
 * Bulk edit names the server's reason for each skipped row, instead of
 * calling every one a "system/orphan row" (#3905).
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
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { BulkEditAddressesModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

describe("Bulk edit skipped rows (#3905)", () => {
  it("says why a row was skipped", async () => {
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: [],
        dns_zone_id: null,
        dns_additional_zone_ids: [],
      }),
    );
    const REASON = "Not in an address set you can edit.";
    answer("ipamApi", "bulkEditAddresses", () =>
      Promise.resolve({
        updated_count: 1,
        skipped: ["i2"],
        skipped_reasons: { i2: REASON },
      }),
    );
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <BulkEditAddressesModal
            ipIds={["i1", "i2"]}
            subnetId="s1"
            onClose={() => {}}
            onDone={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByLabelText("Description"));
    fireEvent.change(screen.getByPlaceholderText(/description/i), {
      target: { value: "x" },
    });
    const apply = screen.getByRole("button", { name: "Apply to all" });
    await waitFor(() =>
      expect((apply as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(apply);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("1 updated; 1 skipped");
    expect(alert.textContent).toContain(REASON);
    expect(alert.textContent).not.toContain("system/orphan");
  });
});

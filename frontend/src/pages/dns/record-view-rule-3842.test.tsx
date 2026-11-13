/**
 * @vitest-environment jsdom
 *
 * The record dialog's View field (#3842).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

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

const { RecordModal } = await import("./DNSPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

function open(ui: ReactNode, isSuperadmin = true) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({ is_superadmin: isSuperadmin, grants: [] }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Add Record View field (#3842)", () => {
  it("does not promise every view, and says what scoping a record does", async () => {
    open(
      <RecordModal
        groupId="grp-1"
        zoneId="zone-1"
        zoneName="corp.example.test."
        onClose={() => {}}
      />,
    );
    const field = (await screen.findByLabelText(/^View/)) as HTMLSelectElement;
    expect(field.textContent ?? "").not.toMatch(/all views|every view/i);
    const rule = screen.getByTestId("record-view-rule").textContent ?? "";
    expect(rule).toMatch(/limits the zone/);
    expect(rule).toMatch(/unscoped record/);
  });
});

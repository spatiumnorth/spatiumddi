/**
 * @vitest-environment jsdom
 *
 * The conformity policy Edit dialog reads the policy when it opens and a Save
 * sends only what the operator changed (#4379).
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

const h = vi.hoisted(() => ({ reads: 0, update: vi.fn() }));

const base = {
  id: "p1",
  name: "Custom policy",
  description: "old description",
  framework: "custom",
  reference: null,
  severity: "warning",
  target_kind: "subnet",
  target_filter: { classification: "pci_scope" },
  check_kind: "has_field",
  check_args: {},
  is_builtin: false,
  enabled: true,
  eval_interval_hours: 24,
  last_evaluated_at: null,
  fail_alert_rule_id: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
// What another client stored after the list loaded.
const stored = {
  ...base,
  description: "changed elsewhere",
  severity: "critical",
};

function list() {
  h.reads += 1;
  return Promise.resolve([h.reads === 1 ? base : stored]);
}

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    conformityApi: {
      ...actual.conformityApi,
      listPolicies: list,
      summary: async () => ({
        overall_pass: 0,
        overall_warn: 0,
        overall_fail: 0,
        overall_not_applicable: 0,
        last_evaluated_at: null,
        frameworks: [],
      }),
      listCheckKinds: async () => [],
      listResults: async () => [],
      updatePolicy: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(stored);
      },
    },
  };
});

const { ConformityPage } = await import("./ConformityPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

async function openEdit() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <ConformityPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByTitle("Edit", {}, { timeout: 10000 }));
  return screen.findByDisplayValue("Custom policy", {}, { timeout: 10000 });
}

describe(
  "Conformity policy Edit reads the row and saves only the change",
  { timeout: 30000 },
  () => {
    it("shows the values stored since the list loaded", async () => {
      await openEdit();
      expect(
        await screen.findByDisplayValue(
          "changed elsewhere",
          {},
          { timeout: 10000 },
        ),
      ).toBeTruthy();
    });

    it("an unrelated Save sends only that field", async () => {
      const name = await openEdit();
      fireEvent.change(name, { target: { value: "Renamed" } });
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(h.update).toHaveBeenCalledWith("p1", { name: "Renamed" });
    });

    it("an untouched Save sends nothing", async () => {
      await openEdit();
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(
        () => expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
        { timeout: 10000 },
      );
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);

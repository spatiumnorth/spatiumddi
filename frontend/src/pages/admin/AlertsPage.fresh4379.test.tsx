/**
 * @vitest-environment jsdom
 *
 * The alert-rule Edit dialog reads the rule when it opens (#4379). It already
 * sent only what the operator changed (#1986), but it was seeded from the list
 * row, so a Save compared against, and showed, values another client had since
 * replaced.
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
  id: "r1",
  name: "Capacity",
  description: "old description",
  enabled: true,
  rule_type: "subnet_utilization",
  threshold_percent: 85,
  threshold_days: null,
  min_free_addresses: null,
  server_type: null,
  classification: null,
  change_scope: null,
  last_scanned_audit_at: null,
  severity: "warning",
  notify_syslog: true,
  notify_webhook: true,
  notify_smtp: false,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
const stored = { ...base, description: "changed elsewhere" };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    alertsApi: {
      ...actual.alertsApi,
      listRules: async () => {
        h.reads += 1;
        return [h.reads === 1 ? base : stored];
      },
      ruleTypes: async () => [],
      listEventsPage: async () => ({ items: [], total: 0 }),
      updateRule: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(stored);
      },
    },
  };
});

const { AlertsPage } = await import("./AlertsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

describe(
  "Alert rule Edit reads the row when it opens",
  { timeout: 30000 },
  () => {
    it("shows the description stored since the list loaded, and Save sends only the name", async () => {
      render(
        <QueryClientProvider
          client={
            new QueryClient({ defaultOptions: { queries: { retry: false } } })
          }
        >
          <MemoryRouter>
            <AlertsPage />
          </MemoryRouter>
        </QueryClientProvider>,
      );
      fireEvent.click(
        await screen.findByTitle(/edit/i, {}, { timeout: 10000 }),
      );
      expect(
        await screen.findByDisplayValue(
          "changed elsewhere",
          {},
          { timeout: 10000 },
        ),
      ).toBeTruthy();
      fireEvent.change(screen.getByDisplayValue("Capacity"), {
        target: { value: "Renamed" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(h.update).toHaveBeenCalledWith("r1", { name: "Renamed" });
    });
  },
);

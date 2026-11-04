/**
 * @vitest-environment jsdom
 *
 * A read-only user's disabled rule-row buttons are named by their action,
 * not by the refusal reason (#3395). `permissionGate()` replaces a control's
 * `title` with the reason while it is denied, so an icon-only button named
 * only by its `title` read "Requires superadmin" three times per row.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const RULE = {
  id: "rule-1",
  name: "Agent config apply rejected",
  description: "",
  enabled: true,
  rule_type: "agent_config_rejected",
  threshold_percent: null,
  threshold_days: null,
  min_free_addresses: null,
  server_type: null,
  classification: null,
  change_scope: null,
  last_scanned_audit_at: null,
  severity: "warning",
  notify_syslog: false,
  notify_webhook: false,
  notify_smtp: false,
  created_at: "2026-11-03T00:00:00.000Z",
  modified_at: "2026-11-03T00:00:00.000Z",
};

const perms = {
  is_superadmin: false,
  grants: [{ action: "read", resource_type: "*" }],
};

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
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "authApi" && method === "myPermissions")
                return async () => perms;
              if (name === "alertsApi" && method === "listRules")
                return async () => [RULE];
              if (name === "alertsApi" && method === "listEvents")
                return async () => [];
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { AlertsPage } = await import("./AlertsPage");

afterEach(cleanup);

describe("AlertsPage rule row for a read-only user (#3395)", () => {
  it("names Disable, Edit and Delete by their action, with the reason as the tooltip", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/admin/alerts"]}>
          <Routes>
            <Route path="/admin/alerts" element={<AlertsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const row = (await screen.findByText(RULE.name)).closest("tr")!;
    await act(async () => {});
    const buttons = within(row).getAllByRole("button");
    expect(
      buttons.map((b) => [
        b.getAttribute("aria-label"),
        b.title,
        (b as HTMLButtonElement).disabled,
      ]),
    ).toEqual([
      ["Disable", "Requires superadmin", true],
      ["Edit", "Requires superadmin", true],
      ["Delete", "Requires superadmin", true],
    ]);
    // And the accessible name is the action, not the refusal.
    for (const name of ["Disable", "Edit", "Delete"])
      expect(within(row).getByRole("button", { name })).toBeTruthy();
    expect(
      within(row).queryAllByRole("button", { name: "Requires superadmin" }),
    ).toEqual([]);
  });
});

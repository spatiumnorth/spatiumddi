/**
 * @vitest-environment jsdom
 *
 * Expanding an audit row shows what the entry recorded (#2009): an upgrade's
 * `direction` and schema check were stored and never shown anywhere.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const entry = vi.hoisted(() => ({
  id: "e1",
  timestamp: "2026-10-16T10:00:00.000Z",
  user_display_name: "alice",
  auth_source: "local",
  action: "appliance.upgrade_scheduled",
  resource_type: "appliance",
  resource_id: "a1",
  resource_display: "node-1",
  result: "success",
  source_ip: null,
}));

const get = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    auditApi: {
      ...actual.auditApi,
      list: vi.fn().mockResolvedValue({ total: 1, items: [entry] }),
      integrity: vi.fn().mockResolvedValue({
        ok: true,
        rows_checked: 1,
        breaks: [],
      }),
      get: (id: string) => get(id),
    },
  };
});

import { AuditPage } from "./AuditPage";

afterEach(cleanup);

describe("AuditPage details", () => {
  it("fetches and shows the recorded details when a row is expanded", async () => {
    get.mockResolvedValue({
      ...entry,
      old_value: null,
      new_value: { direction: "backward", registry_password: "[redacted]" },
      changed_fields: ["desired_appliance_version"],
      error_detail: null,
    });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <AuditPage />
      </QueryClientProvider>,
    );
    expect(screen.queryByText(/"direction"/)).toBeNull();
    fireEvent.click(
      await screen.findByRole("button", { name: /show details/i }),
    );
    expect(await screen.findByText(/"direction": "backward"/)).toBeTruthy();
    expect(screen.getByText(/\[redacted\]/)).toBeTruthy();
    expect(get).toHaveBeenCalledWith("e1");
  });

  it("filters DNS server groups by the type their audit rows carry (#2623)", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <AuditPage />
      </QueryClientProvider>,
    );
    await screen.findByRole("button", { name: /show details/i });
    const values = Array.from(container.querySelectorAll("option")).map(
      (o) => (o as HTMLOptionElement).value,
    );
    // The API writes `dns_server_group`; `dns_group` matches no row.
    expect(values).toContain("dns_server_group");
    expect(values).not.toContain("dns_group");
  });
});

/**
 * @vitest-environment jsdom
 *
 * #4646: a role the supervisor holds back for a missing agent key shows on the
 * Fleet row (chip) and in the drilldown (warning naming the key), instead of
 * the row looking healthy.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ApplianceRow } from "@/lib/api";

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
              typeof method === "symbol" ? undefined : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { ApplianceRoleAssignmentSection, ServiceChipList } =
  await import("./FleetTab");

afterEach(cleanup);

function row(awaiting: string[] | undefined): ApplianceRow {
  return {
    id: "ap-1",
    hostname: "node1",
    state: "approved",
    last_seen_at: new Date().toISOString(),
    assigned_roles: ["dns-bind9", "dhcp"],
    assigned_dns_group_id: null,
    assigned_dhcp_group_id: null,
    capabilities: { can_run_dns_bind9: true, can_run_dhcp: true },
    role_switch_state: "ready",
    role_switch_reason: null,
    roles_awaiting_key: awaiting,
  } as unknown as ApplianceRow;
}

function openDrilldown(r: ApplianceRow) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ApplianceRoleAssignmentSection row={r} onSaved={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Fleet: roles waiting on an agent key (#4646)", () => {
  it("marks the held-back chips and leaves the others alone", () => {
    render(<ServiceChipList row={row(["dhcp"])} />);
    expect(screen.getByText("DHCP · needs key")).toBeTruthy();
    expect(screen.getByText("DNS · BIND9")).toBeTruthy();
  });

  it("warns in the drilldown, naming the missing key and how to set it", () => {
    openDrilldown(row(["dns-bind9", "dhcp"]));
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toMatch(/Waiting on an agent key/);
    expect(alert.textContent).toMatch(/DNS agent key/);
    expect(alert.textContent).toMatch(/DHCP agent key/);
    expect(alert.textContent).toMatch(/Set the .* on the control plane/);
  });

  it("shows nothing when no role is waiting, or an old control plane omits it", () => {
    for (const awaiting of [[], undefined]) {
      cleanup();
      openDrilldown(row(awaiting));
      expect(screen.queryByRole("alert")).toBeNull();
    }
    cleanup();
    render(<ServiceChipList row={row([])} />);
    expect(screen.queryByText(/needs key/)).toBeNull();
  });
});

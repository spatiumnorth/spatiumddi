/**
 * @vitest-environment jsdom
 *
 * A disabled tenant's last error is shown as history, greyed (#2191).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const tenant = (over: Record<string, unknown>) => ({
  id: "1",
  name: "t",
  description: "",
  enabled: true,
  tailnet: "-",
  api_key_present: true,
  api_key_expires_at: null,
  api_key_expiry_source: null,
  credential_state: "rejected",
  credential_days_left: null,
  ipam_space_id: "s",
  dns_group_id: null,
  cgnat_cidr: "",
  ipv6_cidr: "",
  skip_expired: true,
  sync_interval_seconds: 60,
  last_synced_at: null,
  last_sync_error: "Tailscale rejected the API key",
  tailnet_domain: null,
  device_count: null,
  created_at: "",
  modified_at: "",
  ...over,
});

let rows: unknown[] = [];
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    tailscaleApi: {
      ...actual.tailscaleApi,
      listTenants: () => Promise.resolve(rows),
    },
  };
});
vi.mock("@/hooks/useModuleOn", () => ({ useModuleOn: () => true }));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({ isSuperadmin: true, can: () => true }),
  };
});

const { TailscalePage } = await import("./TailscalePage");

afterEach(cleanup);

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TailscalePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Tailscale page, disabled tenant (#2191)", () => {
  it("greys the last error and draws no red Token rejected chip", async () => {
    rows = [tenant({ enabled: false, credential_state: "disabled" })];
    open();
    const err = await screen.findByTestId("tenant-last-error");
    expect(err.textContent).toContain("Last error (disabled)");
    expect(err.className).toContain("text-muted-foreground");
    expect(screen.queryByText("Token rejected")).toBeNull();
  });

  it("keeps the red chip and red error on an enabled rejected tenant", async () => {
    rows = [tenant({})];
    open();
    const err = await screen.findByTestId("tenant-last-error");
    expect(err.className).toContain("text-destructive");
    expect(screen.getByText("Token rejected")).toBeTruthy();
  });
});

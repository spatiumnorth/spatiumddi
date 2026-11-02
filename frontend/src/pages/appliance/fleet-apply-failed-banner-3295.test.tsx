/**
 * @vitest-environment jsdom
 *
 * #3295: the Fleet's "Service lifecycle apply failed" banner says what the
 * supervisor does now.
 *
 * Since #183 Phase 7 the supervisor applies an appliance's roles as a
 * HelmChart through the node's Kubernetes API (k3s); the docker compose path
 * is gone (agent/supervisor/spatium_supervisor/service_lifecycle.py). The
 * banner still said the supervisor's `docker compose` returned a non-zero exit
 * and that "the previous container state remains", above a reason line that
 * names the kube API (`kubeapi /readyz not ok`, `kubeapi apply failed`). A
 * failed apply is not stamped as done, so the next heartbeat applies again.
 *
 * The banner renders inside the drilldown's role assignment section, so these
 * tests render that section from a row alone: every API call stays pending.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
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

const { ApplianceRoleAssignmentSection } = await import("./FleetTab");

afterEach(cleanup);

function row(
  role_switch_state: string | null,
  role_switch_reason: string | null = null,
): ApplianceRow {
  return {
    id: "ap-1",
    hostname: "node1",
    state: "approved",
    assigned_roles: ["dns-bind9"],
    assigned_dns_group_id: null,
    assigned_dhcp_group_id: null,
    capabilities: { can_run_dns_bind9: true, can_run_dhcp: true },
    role_switch_state,
    role_switch_reason,
  } as unknown as ApplianceRow;
}

function open(r: ApplianceRow) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ApplianceRoleAssignmentSection row={r} onSaved={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Fleet: a failed role apply's banner (#3295)", () => {
  // The two kube API reasons the supervisor reports for a failed apply
  // (service_lifecycle.py: the /readyz miss, and the HelmChart write's
  // fallback reason).
  it.each(["kubeapi /readyz not ok", "kubeapi apply failed"])(
    "names the kube API apply, not docker compose, above the reason %s",
    (reason) => {
      open(row("failed", reason));
      const title = screen.getByText("Service lifecycle apply failed");
      const banner = title.parentElement as HTMLElement;
      const body = title.nextElementSibling as HTMLElement;
      expect(body.tagName).toBe("P");

      // What the supervisor does now: it applies the roles through the
      // appliance's Kubernetes API, and the next heartbeat applies again.
      expect(body.textContent).toMatch(/Kubernetes API/);
      expect(body.textContent).toMatch(/next heartbeat/i);

      // Neither the compose command nor container state, anywhere in it.
      expect(banner.textContent).not.toMatch(/docker/i);
      expect(banner.textContent).not.toMatch(/compose/i);
      expect(banner.textContent).not.toMatch(/container state/i);

      // The supervisor's reason still prints under the text.
      const reasonLine = within(banner).getByText(reason);
      expect(
        body.compareDocumentPosition(reasonLine) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    },
  );

  it("shows no failed banner once the apply is ready (control)", () => {
    open(row("ready"));
    expect(screen.getByText("role_switch_state=ready")).toBeTruthy();
    expect(screen.queryByText("Service lifecycle apply failed")).toBeNull();
  });

  it.each([null, "idle"])(
    "shows no lifecycle banner while the state is %s",
    (state) => {
      open(row(state));
      expect(screen.getByText("Firewall profile")).toBeTruthy();
      expect(screen.queryByText("Service lifecycle apply failed")).toBeNull();
      expect(screen.queryByText("role_switch_state=ready")).toBeNull();
    },
  );
});

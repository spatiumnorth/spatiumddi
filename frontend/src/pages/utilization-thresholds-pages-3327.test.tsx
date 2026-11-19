/**
 * @vitest-environment jsdom
 *
 * Settings' Warning / Critical Thresholds band utilization everywhere it is
 * banded, not only in the IPAM tree: the Subnets list's bars and the
 * Dashboard's capacity figures follow them too (#3327).
 */
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const subnet = {
  id: "s1",
  space_id: "sp1",
  block_id: "b1",
  network: "10.152.4.0/28",
  name: "xp",
  gateway: null,
  vlan_id: null,
  status: "active",
  total_ips: 14,
  allocated_ips: 8,
  utilization_percent: 57.14,
};
const calls: Record<string, () => Promise<unknown>> = {
  "settingsApi.get": () =>
    Promise.resolve({
      utilization_warn_threshold: 50,
      utilization_critical_threshold: 95,
      utilization_max_prefix_ipv4: 29,
      utilization_max_prefix_ipv6: 126,
    }),
  "ipamApi.listSubnets": () => Promise.resolve([subnet]),
  "ipamApi.listSpaces": () =>
    Promise.resolve([{ id: "sp1", name: "sp", description: "" }]),
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
                return () =>
                  Promise.resolve({ is_superadmin: true, grants: [] });
              return calls[`${name}.${String(method)}`] ?? pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { SubnetsPage } = await import("@/pages/ipam/SubnetsPage");
const { DashboardPage } = await import("@/pages/DashboardPage");

afterEach(cleanup);

function show(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("utilization thresholds outside the tree (#3327)", () => {
  it("the Subnets list draws a 57% subnet amber under a 50% warning", async () => {
    const { container } = show(<SubnetsPage />);
    await screen.findByText("10.152.4.0/28");
    await vi.waitFor(() =>
      expect(container.querySelector(".bg-amber-400")).not.toBeNull(),
    );
    expect(container.querySelector(".bg-green-500")).toBeNull();
  });

  it("the Dashboard counts a 57% subnet as warning under a 50% warning", async () => {
    show(<DashboardPage />);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 400));
    });
    const text = document.body.textContent ?? "";
    expect(text).toContain("0 at ≥95% · 1 at ≥50%");
    expect(text).not.toContain("no subnet above");
  });
});

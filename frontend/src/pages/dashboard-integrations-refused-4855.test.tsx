/**
 * @vitest-environment jsdom
 *
 * The IPAM tab's Integrations panel and New devices tile say a refused read
 * is refused, not "No clusters registered." or "0" (#4855).
 */
import { act, cleanup, render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const calls: Record<string, () => Promise<unknown>> = {};

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
                  Promise.resolve({ is_superadmin: false, grants: [] });
              const k = `${name}.${String(method)}`;
              if (calls[k]) return calls[k];
              return pending;
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

const { DashboardPage } = await import("@/pages/DashboardPage");

beforeEach(() => {
  for (const k of Object.keys(calls)) delete calls[k];
  localStorage.clear();
});
afterEach(cleanup);

const denied = () =>
  Promise.reject({ response: { status: 403, data: { detail: "Forbidden" } } });

describe("refused IPAM-tab reads (#4855)", () => {
  it("say refused, not empty or zero", async () => {
    calls["settingsApi.get"] = () =>
      Promise.resolve({ integration_kubernetes_enabled: true });
    calls["kubernetesApi.listClusters"] = denied;
    calls["newDeviceApi.summary"] = denied;
    localStorage.setItem("dashboard-tab", "ipam");
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <DashboardPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await act(async () => {
      await new Promise((r) => setTimeout(r, 400));
    });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    const text = document.body.textContent ?? "";
    expect(text).toContain("You don't have permission to see clusters");
    expect(text).toContain("You don't have permission to see new devices");
    expect(text).not.toContain("No clusters registered.");
    expect(text).not.toContain("1 targets");
    expect(text).not.toContain("0 targets");
    expect(text).not.toContain("0 awaiting review");
  });
});

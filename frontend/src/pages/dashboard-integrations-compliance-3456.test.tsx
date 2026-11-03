/**
 * @vitest-environment jsdom
 *
 * An Integrations panel the server withheld is named, never read as "nothing
 * enabled" or an all-clear; the Compliance tab shows a refused read as
 * refused (#3456).
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

const panel = (kind: string, label: string, enabled: boolean) => ({
  kind,
  label,
  enabled,
  target_count: 0,
  healthy_count: 0,
  stale_count: 0,
  error_count: 0,
  warning_count: 0,
  targets: [],
});

const summary = (panels: unknown[], withheld: unknown[]) => ({
  generated_at: "2026-11-03T00:00:00Z",
  panels,
  withheld,
  recent_errors: [],
  recent_warnings: [],
});

beforeEach(() => {
  for (const k of Object.keys(calls)) delete calls[k];
  localStorage.clear();
});
afterEach(cleanup);

async function show(tab: string) {
  localStorage.setItem("dashboard-tab", tab);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
  return document.body.textContent ?? "";
}

const denied = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "Permission denied" } },
  });

describe("withheld Integrations panels (#3456)", () => {
  it("names the withheld integrations and qualifies the all-clears", async () => {
    calls["dashboardsApi.integrationsSummary"] = () =>
      Promise.resolve(
        summary(
          [panel("kubernetes", "Kubernetes", true)],
          [{ kind: "docker", label: "Docker" }],
        ),
      );
    const text = await show("integrations");
    expect(text).toContain("Not visible to your role: Docker.");
    expect(text).toContain(
      "No reconciler errors in the integrations you can read.",
    );
    expect(text).not.toContain("No reconciler errors in recent history.");
  });

  it("only a disabled integration readable is not 'none enabled'", async () => {
    calls["dashboardsApi.integrationsSummary"] = () =>
      Promise.resolve(
        summary(
          [panel("proxmox", "Proxmox VE", false)],
          [{ kind: "docker", label: "Docker" }],
        ),
      );
    const text = await show("integrations");
    expect(text).not.toContain("No integrations are enabled yet");
    expect(text).toContain("No integrations your role can read are enabled");
    expect(text).toContain("Docker");
  });

  it("with nothing withheld the old copy stands", async () => {
    calls["dashboardsApi.integrationsSummary"] = () =>
      Promise.resolve(summary([panel("proxmox", "Proxmox VE", false)], []));
    expect(await show("integrations")).toContain(
      "No integrations are enabled yet",
    );
  });
});

describe("refused Compliance reads (#3456)", () => {
  it("say refused, not empty", async () => {
    calls["alertsApi.listRules"] = denied;
    calls["alertsApi.listEvents"] = denied;
    const text = await show("compliance");
    expect(text).toContain("You don't have permission to see alert rules");
    expect(text).toContain("You don't have permission to see alert events");
    expect(text).not.toContain("No compliance_change rules yet");
    expect(text).not.toContain("No compliance-change events");
  });
});

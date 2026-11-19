/**
 * @vitest-environment jsdom
 *
 * A read the server refused is said to be refused, never drawn as a result:
 * a check still running, a count of zero, empty cards, an empty picker
 * (#3148).
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const answers = new Map<string, () => Promise<unknown>>();

function unavailable() {
  return Promise.reject({
    response: { status: 503, data: { detail: "Service Unavailable" } },
  });
}

function refused(detail: string) {
  return () => Promise.reject({ response: { status: 403, data: { detail } } });
}

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
              return (...a: unknown[]) => {
                void a;
                const f = answers.get(`${name}.${String(method)}`);
                return f ? f() : pending();
              };
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

const { AuditPage } = await import("@/pages/admin/AuditPage");
const { AIToolCatalogPage } = await import("@/pages/admin/AIToolCatalogPage");
const { ConformityPanel } = await import("@/pages/DashboardPage");
const { ServerDetailModal } = await import("@/pages/dns/ServerDetailModal");
const { ResourcesTab } = await import("@/pages/network/ServicesPage");

beforeEach(() => {
  answers.clear();
  answers.set("authApi.myPermissions", () =>
    Promise.resolve({
      is_superadmin: false,
      grants: [{ action: "read", resource_type: "*", resource_id: null }],
    }),
  );
});
afterEach(cleanup);

async function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 100));
  });
}

describe("refused reads are not shown as results (#3148)", () => {
  it("the Audit Log chain badge does not claim a check is still running", async () => {
    answers.set("auditApi.integrity", refused("need 'read' on 'audit_log'"));
    answers.set("auditApi.list", refused("need 'read' on 'audit_log'"));
    await show(<AuditPage />);
    expect(document.body.textContent).not.toContain("Checking integrity");
    expect(document.body.textContent).toContain(
      "Integrity check not permitted",
    );
  });

  it("the AI Tool Catalog does not count tools it was refused", async () => {
    answers.set("aiToolCatalogApi.list", refused("Superadmin required"));
    await show(<AIToolCatalogPage />);
    expect(document.body.textContent).not.toContain("0 of 0 enabled");
    expect(document.body.textContent).toContain(
      "You don't have permission to see the AI tool catalog",
    );
  });

  it("the Conformity tab does not draw zeros over a refused summary", async () => {
    answers.set("conformityApi.summary", refused("Permission denied"));
    answers.set("conformityApi.listResults", refused("Permission denied"));
    await show(<ConformityPanel />);
    const text = document.body.textContent ?? "";
    expect(text).toContain(
      "You don't have permission to see conformity results",
    );
    expect(text).not.toContain("Frameworks");
    expect(text).not.toContain("Nothing currently failing");
  });

  it("a server's Stats tab does not show empty cards under the refusal", async () => {
    answers.set("logsApi.dnsQueryAnalytics", refused("Permission denied"));
    await show(
      <ServerDetailModal
        server={
          {
            id: "s1",
            group_id: "g1",
            name: "ns1",
            driver: "bind9",
            roles: [],
            host: "192.0.2.53",
            port: 53,
            is_primary: true,
            is_enabled: true,
            status: "active",
          } as never
        }
        onClose={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /^Stats/ }));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 100));
    });
    const text = document.body.textContent ?? "";
    expect(text).toContain(
      "You don't have permission to see this server's query",
    );
    expect(text).not.toContain("No data in window.");
  });

  it("a read that failed for another reason says so, not that it was refused", async () => {
    answers.set("auditApi.integrity", unavailable);
    answers.set("auditApi.list", unavailable);
    await show(<AuditPage />);
    let text = document.body.textContent ?? "";
    expect(text).not.toContain("Checking integrity");
    expect(text).toContain("Integrity check unavailable");
    expect(text).not.toContain("not permitted");
    cleanup();

    answers.set("logsApi.dnsQueryAnalytics", unavailable);
    await show(
      <ServerDetailModal
        server={
          {
            id: "s1",
            group_id: "g1",
            name: "ns1",
            driver: "bind9",
            roles: [],
            host: "192.0.2.53",
            port: 53,
            is_primary: true,
            is_enabled: true,
            status: "active",
          } as never
        }
        onClose={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /^Stats/ }));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 100));
    });
    text = document.body.textContent ?? "";
    expect(text).toContain("Couldn't load this server's query analytics");
    expect(text).not.toContain("No data in window.");
    expect(text).not.toContain("permission");
  });

  it("the VRF picker says why it is empty and is disabled", async () => {
    answers.set("vrfsApi.list", refused("Permission denied"));
    await show(
      <ResourcesTab
        service={{ id: "svc", kind: "custom", resources: [] } as never}
        onChange={() => {}}
      />,
    );
    expect(document.body.textContent).toContain(
      "You don't have permission to see VRF resources",
    );
    const sel = screen.getAllByRole("combobox")[1] as HTMLSelectElement;
    expect(sel.disabled).toBe(true);
  });
});

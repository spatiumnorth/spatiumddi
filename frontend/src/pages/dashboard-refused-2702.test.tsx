/**
 * @vitest-environment jsdom
 *
 * The Dashboard asks for the audit log and the certificate list only when
 * the user may read them, and says so in the card when it may not, instead
 * of "No recent activity" / "0 of 0 monitored" (#2702).
 */
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const auditList = vi.fn();
const certList = vi.fn();
let grants: unknown[] = [];

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
                return () => Promise.resolve({ is_superadmin: false, grants });
              if (name === "auditApi" && method === "list") return auditList;
              if (name === "tlsCertsApi" && method === "list") return certList;
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
  auditList.mockReset();
  certList.mockReset();
  auditList.mockResolvedValue({ items: [], total: 0 });
  certList.mockResolvedValue({ items: [], total: 0 });
});
afterEach(cleanup);

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 300));
  });
}

describe("Dashboard without audit_log / tls_cert read", () => {
  it("does not ask for them and says they are withheld", async () => {
    grants = [{ action: "read", resource_type: "subnet", resource_id: null }];
    await show();
    expect(auditList).not.toHaveBeenCalled();
    expect(certList).not.toHaveBeenCalled();
    const text = document.body.textContent ?? "";
    expect(text).toContain("You don't have permission to see the audit log");
    expect(text).not.toContain("No recent activity");
    expect(text).not.toContain("of 0 monitored");
    expect(text).toContain("you may not read certificates");
  });

  it("asks and keeps the empty state for a user who may read them", async () => {
    grants = [
      { action: "read", resource_type: "audit_log", resource_id: null },
      { action: "read", resource_type: "tls_cert", resource_id: null },
    ];
    await show();
    expect(auditList).toHaveBeenCalled();
    expect(certList).toHaveBeenCalled();
    expect(document.body.textContent).toContain("No recent activity");
  });

  it("says a refused audit read was refused", async () => {
    grants = [
      { action: "read", resource_type: "audit_log", resource_id: null },
    ];
    auditList.mockImplementation(() =>
      Promise.reject({
        response: {
          status: 403,
          data: { detail: "need 'read' on 'audit_log'" },
        },
      }),
    );
    await show();
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "You don't have permission to see the audit log (need 'read'",
      ),
    );
    expect(document.body.textContent).not.toContain("No recent activity");
  });
});

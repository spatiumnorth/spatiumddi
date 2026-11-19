/**
 * @vitest-environment jsdom
 *
 * A domain's own page offers Refresh WHOIS only to a user who may write
 * domains, and says when the server refuses it (#2519).
 *
 * The Domains list was gated (#1341), the detail page was not: a Viewer
 * pressed Refresh WHOIS, the API answered 403, and the page showed nothing.
 * Real `usePermissions`, answered from `GET /auth/me/permissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DomainDetailPage } = await import("./DomainDetailPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const DOMAIN = {
  id: "dom-1",
  name: "viewer-walk.test",
  registrar: null,
  expires_at: null,
  whois_state: "ok",
  nameservers: [],
  tags: {},
};

type Grants = [string, string][] | "superadmin";

async function open(grants: Grants, refresh?: Answer) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type]) => ({
                action,
                resource_type,
                resource_id: null,
              })),
            },
      ),
  };
  answers.domainsApi = {
    get: () => Promise.resolve(DOMAIN),
    ...(refresh ? { refreshWhois: refresh } : {}),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/admin/domains/dom-1"]}>
        <Routes>
          <Route path="/admin/domains/:id" element={<DomainDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("viewer-walk.test");
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

const refreshButton = () =>
  screen.getByRole("button", { name: /Refresh WHOIS/ }) as HTMLButtonElement;

describe("a domain's page (#2519)", () => {
  it("offers a read-only Viewer no Refresh WHOIS, and says why", async () => {
    await open([["read", "*"]]);
    expect(refreshButton().disabled).toBe(true);
    expect(refreshButton().title).toBe("Requires write permission on domains");
  });

  it("offers a superadmin and a domains writer Refresh WHOIS", async () => {
    await open("superadmin");
    expect(refreshButton().disabled).toBe(false);
    cleanup();
    await open([
      ["read", "*"],
      ["write", "manage_domains"],
    ]);
    expect(refreshButton().disabled).toBe(false);
  });

  it("says a refused refresh was refused", async () => {
    const refusal = Object.assign(new Error("403"), {
      isAxiosError: true,
      response: { status: 403, data: { detail: "Permission denied" } },
    });
    await open("superadmin", () => Promise.reject(refusal));
    fireEvent.click(refreshButton());
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/Permission denied/);
  });
});

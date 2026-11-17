/**
 * @vitest-environment jsdom
 *
 * When the caller's own permissions read fails, ``can`` answers false for
 * everyone, the superadmin included. The Dashboard's cards gated on it say
 * the permissions could not be read, never that the role lacks the grant
 * (#3541).
 */
import {
  act,
  cleanup,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

const perms = vi.hoisted(() => ({
  fn: (() => Promise.reject(new Error("Network Error"))) as () => Promise<{
    is_superadmin: boolean;
    grants: unknown[];
  }>,
}));

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
                return () => perms.fn();
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

const { DashboardPage, DNSThreatCard } = await import("@/pages/DashboardPage");
const { usePermissions } = await import("@/hooks/usePermissions");

afterEach(() => {
  cleanup();
  perms.fn = () => Promise.reject(new Error("Network Error"));
});

function client() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

async function show(el: ReactNode) {
  render(
    <QueryClientProvider client={client()}>
      <MemoryRouter>{el}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 300));
  });
}

describe("a failed permissions read is not a missing grant (#3541)", () => {
  it("the DNS tunneling card says the permissions could not be read", async () => {
    await show(<DNSThreatCard />);
    expect(screen.getByText(/permissions could not be read/)).toBeTruthy();
    expect(screen.queryByText(/your role does not have/)).toBeNull();
  });

  it("the DNS tunneling card keeps the role words for a real missing grant", async () => {
    perms.fn = () =>
      Promise.resolve({
        is_superadmin: false,
        grants: [
          { action: "read", resource_type: "subnet", resource_id: null },
        ],
      });
    await show(<DNSThreatCard />);
    expect(screen.getByText(/your role does not have/)).toBeTruthy();
    expect(screen.queryByText(/could not be read/)).toBeNull();
  });

  it("the audit card and the certificates tile say so too", async () => {
    await show(<DashboardPage />);
    const text = document.body.textContent ?? "";
    expect(text).toContain(
      "Your permissions could not be read, so the audit log was not requested",
    );
    expect(text).not.toContain(
      "You don't have permission to see the audit log",
    );
    expect(text).toContain("couldn't read your permissions");
    expect(text).not.toContain("you may not read certificates");
  });

  it("a failed refetch over grants already read is not a failed read", async () => {
    const qc = client();
    perms.fn = () =>
      Promise.resolve({
        is_superadmin: false,
        grants: [
          { action: "read", resource_type: "subnet", resource_id: null },
        ],
      });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => usePermissions(), { wrapper });
    await waitFor(() =>
      expect(result.current.can("read", "subnet")).toBe(true),
    );
    perms.fn = () => Promise.reject(new Error("Network Error"));
    await act(async () => {
      await qc.refetchQueries({ queryKey: ["my-permissions"] });
      // Let the observer's batched notification re-render the hook.
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(qc.getQueryState(["my-permissions"])?.status).toBe("error");
    // ``can`` still answers from the grants read before, so "the role
    // lacks this" stays true where it is, and isError must not contradict it.
    expect(result.current.can("read", "subnet")).toBe(true);
    expect(result.current.isError).toBe(false);
  });
});

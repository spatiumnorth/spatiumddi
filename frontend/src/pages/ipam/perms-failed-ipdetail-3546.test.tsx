/**
 * @vitest-environment jsdom
 *
 * When the caller's permissions read fails, ``can`` is false for everyone.
 * The IP detail's blocklist and profile-scan sections say the permissions
 * could not be read, not that the role lacks the grant (#3546).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress } from "@/lib/api";

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
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { IPDetailModal } = await import("./IPDetailModal");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";
const ADDR = {
  id: "a1",
  subnet_id: "s1",
  address: "10.71.1.10",
  status: "allocated",
  role: null,
  hostname: "h",
  fqdn: null,
  description: "",
  mac_address: null,
  tags: {},
  custom_fields: {},
  last_profile_scan_id: "scan1",
  last_profiled_at: STAMP,
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as IPAddress;

function openDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <IPDetailModal
          address={ADDR}
          canEdit={true}
          onClose={() => {}}
          onEdit={() => {}}
          onScan={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("IP detail when the permissions read failed (#3546)", () => {
  it("says so in the blocklist and profile-scan sections", async () => {
    answers.authApi = {
      myPermissions: () => Promise.reject(new Error("Network Error")),
    };
    openDetail();
    await waitFor(() =>
      expect(document.body.textContent).toContain("could not be read"),
    );
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("don't have permission to see this IP's");
    expect(text).toContain("Reload to try again");
    // One notice per section: the blocklist status and the profile scan.
    expect(text.split("could not be read").length - 1).toBeGreaterThanOrEqual(
      2,
    );
  });

  it("keeps the role wording for a grant the user really lacks", async () => {
    answers.authApi = {
      myPermissions: () =>
        Promise.resolve({
          is_superadmin: false,
          grants: [{ action: "read", resource_type: "ip_address" }],
        }),
    };
    openDetail();
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "don't have permission to see this IP's blocklist status",
      ),
    );
    expect(document.body.textContent).not.toContain("could not be read");
  });
});

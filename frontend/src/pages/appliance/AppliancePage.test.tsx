/**
 * @vitest-environment jsdom
 *
 * #3067 — a DNS Editor holds `admin` on `certificate_store` and nothing on
 * `appliance`, so `GET /appliance/info` answers them 403. Following the
 * DoT / DoH card's link onto an appliance, they must still get the
 * appliance's store — the served certificate marked Active and not
 * deletable — not the Docker / Kubernetes form. Which install this is
 * comes from the public `/version`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const { refused, mocks } = vi.hoisted(() => {
  const refused = () =>
    Promise.reject(
      Object.assign(new Error("Request failed with status code 403"), {
        isAxiosError: true,
        response: { status: 403, data: { detail: "Forbidden" } },
      }),
    );
  return {
    refused,
    mocks: {
      getInfo: vi.fn(),
      version: vi.fn(),
      certs: [
        {
          id: "1",
          name: "served-cert",
          source: "uploaded",
          is_active: true,
          pending: false,
          subject_cn: "ddi.example.com",
          sans: ["ddi.example.com"],
          issuer_cn: "CA",
          fingerprint_sha256: "ab",
          valid_from: "2026-01-01T00:00:00Z",
          valid_to: "2099-01-01T00:00:00Z",
          notes: null,
        },
        {
          id: "2",
          name: "dot-cert",
          source: "uploaded",
          is_active: false,
          pending: false,
          subject_cn: "dns.example.com",
          sans: [],
          issuer_cn: "CA",
          fingerprint_sha256: "cd",
          valid_from: "2026-01-01T00:00:00Z",
          valid_to: "2099-01-01T00:00:00Z",
          notes: null,
        },
      ],
    },
  };
});

vi.mock("@/lib/api", async (importOriginal) => {
  const orig = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...orig,
    authApi: {
      ...orig.authApi,
      me: vi.fn().mockResolvedValue({ is_superadmin: false }),
    },
    applianceApi: { ...orig.applianceApi, getInfo: mocks.getInfo },
    versionApi: { get: mocks.version },
    applianceTlsApi: {
      list: vi.fn().mockResolvedValue(mocks.certs),
      activate: vi.fn(),
      remove: vi.fn(),
      upload: vi.fn(),
    },
    applianceAcmeApi: {
      listOrders: vi.fn().mockResolvedValue([]),
      getAccount: vi.fn().mockResolvedValue(null),
    },
    applianceApprovalApi: {
      ...orig.applianceApprovalApi,
      listFleet: vi.fn().mockImplementation(refused),
      getMetalLBConfig: vi.fn().mockImplementation(refused),
    },
  };
});
// A DNS Editor: the store, and nothing on `appliance`.
vi.mock("@/hooks/usePermissions", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/usePermissions")>()),
  usePermissions: () => ({
    can: (_action: string, rtype: string) => rtype === "certificate_store",
    isSuperadmin: false,
    isLoading: false,
  }),
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true }),
}));
vi.mock("@/hooks/useModuleOn", () => ({ useModuleOn: () => true }));

import { AppliancePage } from "./AppliancePage";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  sessionStorage.clear();
});

describe("AppliancePage for a certificate-store-only caller (#3067)", () => {
  it("shows the appliance's store when /appliance/info is refused", async () => {
    mocks.getInfo.mockImplementation(refused);
    mocks.version.mockResolvedValue({ version: "t", appliance_mode: true });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/appliance?tab=tls"]}>
          <AppliancePage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText("served-cert");
    await waitFor(() => expect(mocks.getInfo).toHaveBeenCalled());
    expect(await screen.findByText("Web UI Certificate")).toBeTruthy();
    expect(screen.queryByText("TLS certificates")).toBeNull();
    expect(screen.queryByText("docker/k8s")).toBeNull();
    expect(screen.getByText("Active")).toBeTruthy();
    const [servedDelete, dotDelete] = screen
      .getAllByText("Delete")
      .map((el) => el.closest("button")!);
    expect(servedDelete.disabled).toBe(true);
    expect(dotDelete.disabled).toBe(false);
    // Host tabs stay hidden: everything inside them would be refused.
    expect(screen.queryByRole("button", { name: /Cluster/ })).toBeNull();
  });
});

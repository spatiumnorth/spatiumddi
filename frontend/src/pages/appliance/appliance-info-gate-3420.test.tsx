/**
 * @vitest-environment jsdom
 *
 * #3420: `GET /appliance/info` takes `read` on `appliance`. #3067's DNS
 * Editor (`admin` on `certificate_store`, nothing on `appliance`) reaches
 * the Appliance page for the certificate store alone, and the page asked
 * `/appliance/info` on every load: refused each time, each refusal a
 * `denied` audit row under the editor's name. The page asks it only of a
 * caller who may read it, matched by `usePermissions` against the caller's
 * own grants. An appliance reader is still asked, and still gets what the
 * answer carries: the version and hostname in the header, and the host tabs.
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
      myPermissions: vi.fn(),
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
      myPermissions: mocks.myPermissions,
    },
    applianceApi: { ...orig.applianceApi, getInfo: mocks.getInfo },
    versionApi: {
      get: vi.fn().mockResolvedValue({ version: "t", appliance_mode: true }),
    },
    applianceTlsApi: {
      list: vi.fn().mockResolvedValue([
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
      ]),
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
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true }),
}));
vi.mock("@/hooks/useModuleOn", () => ({ useModuleOn: () => true }));

import { AppliancePage } from "./AppliancePage";

// The built-in DNS Editor's grants (backend/app/main.py): the certificate
// store, and nothing on `appliance`.
const DNS_EDITOR: [string, string][] = [
  ["admin", "dns_group"],
  ["admin", "dns_zone"],
  ["admin", "dns_record"],
  ["admin", "dns_blocklist"],
  ["admin", "certificate_store"],
  ["read", "manage_dns_pools"],
  ["read", "alert"],
];

function signInAs(grants: [string, string][]) {
  mocks.myPermissions.mockResolvedValue({
    is_superadmin: false,
    grants: grants.map(([action, resource_type]) => ({
      action,
      resource_type,
      resource_id: null,
    })),
  });
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/appliance"]}>
        <AppliancePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  sessionStorage.clear();
});

describe("AppliancePage asks /appliance/info only of a caller who may read it (#3420)", () => {
  it("does not ask a certificate-store-only caller, whose store still works", async () => {
    signInAs(DNS_EDITOR);
    mocks.getInfo.mockImplementation(refused);
    renderPage();
    // The store renders once the caller's permissions say it may be read.
    await screen.findByText("served-cert");
    expect(mocks.myPermissions).toHaveBeenCalled();
    expect(screen.getByText("Web UI Certificate")).toBeTruthy();
    expect(mocks.getInfo).not.toHaveBeenCalled();
    // Host tabs stay hidden: everything inside them would be refused.
    expect(screen.queryByRole("button", { name: /Cluster/ })).toBeNull();
  });

  it("still asks an appliance reader, and shows what the answer carries", async () => {
    signInAs([["read", "appliance"]]);
    mocks.getInfo.mockResolvedValue({
      appliance_mode: true,
      appliance_version: "2026.11.03-1",
      appliance_hostname: "ddi-node-1",
      self_appliance: null,
    });
    renderPage();
    await waitFor(() => expect(mocks.getInfo).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("v2026.11.03-1")).toBeTruthy();
    expect(screen.getByText("ddi-node-1")).toBeTruthy();
    expect(await screen.findByRole("button", { name: /Cluster/ })).toBeTruthy();
    await screen.findByText("served-cert");
  });

  it("keeps a reader refused anyway on the appliance's own form (#3067)", async () => {
    signInAs([["read", "appliance"]]);
    mocks.getInfo.mockImplementation(refused);
    renderPage();
    await waitFor(() => expect(mocks.getInfo).toHaveBeenCalled());
    await screen.findByText("served-cert");
    expect(screen.getByText("Web UI Certificate")).toBeTruthy();
    expect(screen.queryByText("docker/k8s")).toBeNull();
    expect(screen.queryByRole("button", { name: /Cluster/ })).toBeNull();
  });
});

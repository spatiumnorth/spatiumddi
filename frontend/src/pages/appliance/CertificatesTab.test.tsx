/**
 * @vitest-environment jsdom
 *
 * #3061 — the certificate store is reachable on Docker Compose / Kubernetes
 * too. Off-appliance it lists, uploads and issues, but never offers to
 * activate a cert as the Web UI certificate.
 *
 * #3067 — the controls follow the store's own permission, and activation
 * follows `admin` on `appliance`. Which install this is comes from the
 * public `/version`, never from `/appliance/info`, which a store-only
 * caller is refused.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const certs = vi.hoisted(() => [
  {
    id: "1",
    name: "issued-cert",
    source: "letsencrypt",
    is_active: true,
    pending: false,
    subject_cn: "dns.example.com",
    sans: ["dns.example.com"],
    issuer_cn: "R11",
    fingerprint_sha256: "ab",
    valid_from: "2026-01-01T00:00:00Z",
    valid_to: "2099-01-01T00:00:00Z",
    notes: null,
  },
  {
    id: "2",
    name: "other-cert",
    source: "uploaded",
    is_active: false,
    pending: false,
    subject_cn: "b.example.com",
    sans: [],
    issuer_cn: "CA",
    fingerprint_sha256: "cd",
    valid_from: "2026-01-01T00:00:00Z",
    valid_to: "2099-01-01T00:00:00Z",
    notes: null,
  },
]);

// What the deployment answers: `/version` (public) and the appliance's own
// `/appliance/info` + system info (read on `appliance`).
const appliance = vi.hoisted(() => ({
  mode: true,
  getInfo: vi.fn(),
  systemInfo: vi.fn(),
  version: vi.fn(),
}));
vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  applianceTlsApi: {
    list: vi.fn().mockResolvedValue(certs),
    activate: vi.fn(),
    remove: vi.fn(),
    upload: vi.fn(),
  },
  applianceAcmeApi: {
    listOrders: vi.fn().mockResolvedValue([]),
    getAccount: vi.fn().mockResolvedValue(null),
  },
  applianceApi: { getInfo: appliance.getInfo },
  applianceSystemApi: { info: appliance.systemInfo },
  versionApi: { get: appliance.version },
}));
// The caller's grants, as `action:resource_type` ("*" for a superadmin).
const grants = vi.hoisted(() => ({ current: new Set<string>(["*"]) }));
vi.mock("@/hooks/usePermissions", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/usePermissions")>()),
  usePermissions: () => ({
    can: (action: string, rtype: string) =>
      grants.current.has("*") ||
      grants.current.has(`${action}:${rtype}`) ||
      grants.current.has(`admin:${rtype}`),
    isSuperadmin: grants.current.has("*"),
    isLoading: false,
  }),
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true }),
}));

import { CertificatesTab } from "./CertificatesTab";

beforeEach(() => {
  appliance.version.mockImplementation(async () => ({
    version: "test",
    appliance_mode: appliance.mode,
  }));
  appliance.getInfo.mockResolvedValue({ appliance_mode: appliance.mode });
  appliance.systemInfo.mockResolvedValue({});
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  grants.current = new Set(["*"]);
});

function renderTab(isApplianceHost: boolean) {
  appliance.mode = isApplianceHost;
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <CertificatesTab />
    </QueryClientProvider>,
  );
}

describe("CertificatesTab off-appliance", () => {
  it("lists certs, offers upload + ACME, hides activation", async () => {
    renderTab(false);
    await screen.findByText("issued-cert");
    expect(screen.getByText("other-cert")).toBeTruthy();
    expect(screen.getByText("TLS certificates")).toBeTruthy();
    expect(screen.getByText("Upload certificate")).toBeTruthy();
    expect(screen.getByText("Issue via Let's Encrypt")).toBeTruthy();
    expect(screen.queryByText("Activate")).toBeNull();
    expect(screen.queryByText("Active")).toBeNull();
    // An ACME-issued row is deletable: nothing is serving it.
    const del = screen.getAllByText("Delete")[0].closest("button")!;
    expect(del.disabled).toBe(false);
    fireEvent.click(screen.getByText("Upload certificate"));
    await screen.findByText("Private key PEM");
    expect(screen.queryByText("Activate immediately")).toBeNull();
  });

  it("keeps activation on an appliance host", async () => {
    renderTab(true);
    await screen.findByText("issued-cert");
    expect(screen.getByText("Web UI Certificate")).toBeTruthy();
    expect(screen.getByText("Activate")).toBeTruthy();
    expect(screen.getByText("Active")).toBeTruthy();
    fireEvent.click(screen.getByText("Upload certificate"));
    await screen.findByText("Activate immediately");
  });
});

describe("CertificatesTab permissions (#3067)", () => {
  it("lets a certificate-store admin manage the store but not activate", async () => {
    grants.current = new Set(["admin:certificate_store"]);
    renderTab(true);
    await screen.findByText("issued-cert");
    const upload = screen.getByText("Upload certificate").closest("button")!;
    expect(upload.disabled).toBe(false);
    const activate = screen.getByText("Activate").closest("button")!;
    expect(activate.disabled).toBe(true);
    expect(activate.title).toMatch(/admin permission on the appliance/);
    expect(screen.getAllByText("Delete")[1].closest("button")!.disabled).toBe(
      false,
    );
    fireEvent.click(upload);
    await screen.findByText("Private key PEM");
    expect(screen.queryByText("Activate immediately")).toBeNull();
  });

  it("leaves a read-only caller nothing to click", async () => {
    grants.current = new Set(["read:certificate_store"]);
    renderTab(false);
    await screen.findByText("issued-cert");
    const upload = screen.getByText("Upload certificate").closest("button")!;
    expect(upload.disabled).toBe(true);
    expect(upload.title).toMatch(/certificate_store/);
    for (const del of screen.getAllByText("Delete")) {
      expect(del.closest("button")!.disabled).toBe(true);
    }
  });
});

describe("CertificatesTab on an appliance, as a store-only caller (#3067)", () => {
  // A DNS Editor: admin on certificate_store, nothing on appliance — so
  // `/appliance/info` answers 403. The page must still know it is on an
  // appliance, from `/version`.
  const refused = () =>
    Promise.reject(
      Object.assign(new Error("Request failed with status code 403"), {
        isAxiosError: true,
        response: { status: 403, data: { detail: "Forbidden" } },
      }),
    );

  it("keeps the served cert's Active badge and its Delete disabled", async () => {
    grants.current = new Set(["admin:certificate_store"]);
    appliance.getInfo.mockImplementation(refused);
    appliance.systemInfo.mockImplementation(refused);
    renderTab(true);
    await screen.findByText("issued-cert");
    await waitFor(() => expect(appliance.version).toHaveBeenCalled());
    expect(await screen.findByText("Web UI Certificate")).toBeTruthy();
    expect(screen.queryByText("TLS certificates")).toBeNull();
    expect(screen.getByText("Active")).toBeTruthy();
    const [servedDelete, otherDelete] = screen
      .getAllByText("Delete")
      .map((el) => el.closest("button")!);
    expect(servedDelete.disabled).toBe(true);
    expect(servedDelete.title).toMatch(/Activate a different certificate/);
    expect(otherDelete.disabled).toBe(false);
    // Nothing on the page needed the appliance's own info to decide that,
    // and the ACME prefill does not ask for what it would be refused.
    fireEvent.click(screen.getByText("Issue via Let's Encrypt"));
    await screen.findByText("Issue via Let's Encrypt", { selector: "h2" });
    expect(appliance.getInfo).not.toHaveBeenCalled();
    expect(appliance.systemInfo).not.toHaveBeenCalled();
  });

  it("treats an unknown deployment as an appliance", async () => {
    grants.current = new Set(["admin:certificate_store"]);
    appliance.version.mockImplementation(refused);
    renderTab(true);
    await screen.findByText("issued-cert");
    await waitFor(() => expect(appliance.version).toHaveBeenCalled());
    expect(screen.getByText("Active")).toBeTruthy();
    expect(screen.getAllByText("Delete")[0].closest("button")!.disabled).toBe(
      true,
    );
  });
});

/**
 * @vitest-environment jsdom
 *
 * #3061 — the certificate store is reachable on Docker Compose / Kubernetes
 * too. Off-appliance it lists, uploads and issues, but never offers to
 * activate a cert as the Web UI certificate.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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
  applianceApi: { getInfo: vi.fn().mockResolvedValue({}) },
  applianceSystemApi: { info: vi.fn().mockResolvedValue({}) },
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true }),
}));

import { CertificatesTab } from "./CertificatesTab";

afterEach(cleanup);

function renderTab(isApplianceHost: boolean) {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <CertificatesTab isApplianceHost={isApplianceHost} />
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

/**
 * @vitest-environment jsdom
 *
 * Re-profile now started a scan a user without read on 'manage_nmap_scans'
 * (the built-in IPAM Editor) could never read back, leaving the button on
 * "Scanning…" for as long as the modal was open (#3271). It is now offered
 * only to a user who can read the scan.
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

function signInAs(grants: [string, string][]) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: false,
        grants: grants.map(([action, resource_type]) => ({
          action,
          resource_type,
          resource_id: null,
        })),
      }),
  };
}

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

const buttons = () =>
  Array.from(document.querySelectorAll("button")).map((b) => b.textContent);

describe("Device profile re-profile", () => {
  it("is not offered, and the scan is not read, without read on manage_nmap_scans", async () => {
    signInAs([
      ["read", "ip_address"],
      ["write", "ip_address"],
    ]);
    const getScan = vi.fn(() => Promise.resolve({}));
    answers.nmapApi = { getScan };
    openDetail();
    await waitFor(() =>
      expect(document.body.textContent).toContain("Device profile"),
    );
    await new Promise((r) => setTimeout(r, 50));
    expect(buttons().some((t) => t?.includes("Re-profile now"))).toBe(false);
    expect(getScan).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain(
      "don't have permission to see this IP's profile scan",
    );
  });

  it("is offered with the grant", async () => {
    signInAs([
      ["read", "ip_address"],
      ["write", "ip_address"],
      ["read", "manage_nmap_scans"],
    ]);
    answers.nmapApi = { getScan: () => new Promise(() => {}) };
    openDetail();
    await waitFor(() =>
      expect(buttons().some((t) => t?.includes("Re-profile now"))).toBe(true),
    );
  });
});

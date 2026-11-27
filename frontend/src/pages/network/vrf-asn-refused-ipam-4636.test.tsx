/**
 * @vitest-environment jsdom
 *
 * A VRF's page and an ASN's page do not tell a role refused the IP space and
 * block lists (the built-in Network Editor) that the VRF / ASN is linked to
 * none (#4636). A refusal is said, the VRF's own server counts still show,
 * and a superadmin / reader whose lists answered sees the real rows.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const VRF = {
  id: "v1",
  name: "corp",
  description: "",
  asn_id: null,
  route_distinguisher: null,
  import_targets: [],
  export_targets: [],
  tags: {},
  custom_fields: {},
  customer_id: null,
  created_at: "2026-11-01T00:00:00Z",
  modified_at: "2026-11-01T00:00:00Z",
  space_count: 1,
  block_count: 1,
};
const ASN = {
  id: "a1",
  number: 4200009601,
  name: "lab",
  description: "",
  kind: "private",
  holder_org: null,
  registry: "private",
  whois_state: "n/a",
  whois_last_checked_at: null,
  whois_data: null,
  tags: {},
  custom_fields: {},
};
const SPACE = {
  id: "s1",
  name: "our-space",
  description: "",
  vrf_id: "v1",
  asn_id: "a1",
};
const BLOCK = {
  id: "b1",
  name: "our-block",
  network: "10.9.0.0/16",
  description: "",
  vrf_id: "v1",
  asn_id: "a1",
};

type Mode = "403" | "ok";
let mode: Mode = "403";
const refused = () =>
  Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: { status: 403, data: { detail: "Permission denied" } },
  });

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const lists = (rows: unknown[]) => async () =>
    mode === "403" ? Promise.reject(refused()) : rows;
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
                return async () => ({ is_superadmin: true, grants: [] });
              if (name === "vrfsApi" && method === "get")
                return async () => VRF;
              if (name === "asnsApi" && method === "get")
                return async () => ASN;
              if (name === "ipamApi" && method === "listSpaces")
                return lists([SPACE]);
              if (name === "ipamApi" && method === "listBlocks")
                return lists([BLOCK]);
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => false }),
}));

const { VRFDetailPage } = await import("@/pages/vrfs/VRFDetailPage");
const { AsnDetailPage } = await import("./AsnDetailPage");

afterEach(() => {
  cleanup();
  mode = "403";
});

function show(path: string, route: string, el: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={el} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("VRF page, IP space / block lists refused (#4636)", () => {
  it("says the lists are not visible and shows the server's counts", async () => {
    show("/network/vrfs/v1", "/network/vrfs/:id", <VRFDetailPage />);
    expect(await screen.findByText("IP Spaces (1)")).toBeTruthy();
    expect(screen.getByText("IP Blocks (1)")).toBeTruthy();
    expect(
      await screen.findByText(/don't have permission to see IP spaces/),
    ).toBeTruthy();
    fireEvent.click(screen.getByText("IP Blocks (1)"));
    expect(
      await screen.findByText(/don't have permission to see IP blocks/),
    ).toBeTruthy();
    expect(screen.queryByText(/No IP (spaces|blocks) linked/)).toBeNull();
    expect(screen.queryByText(/\(0\)/)).toBeNull();
  });

  it("lists the linked rows for a role that can read them", async () => {
    mode = "ok";
    show("/network/vrfs/v1", "/network/vrfs/:id", <VRFDetailPage />);
    expect(await screen.findByText("IP Spaces (1)")).toBeTruthy();
    expect(await screen.findByText("our-space")).toBeTruthy();
  });
});

describe("ASN page, IP space / block lists refused (#4636)", () => {
  it("says the lists are not visible, not 'No linked spaces/blocks'", async () => {
    show("/network/asns/a1", "/network/asns/:id", <AsnDetailPage />);
    fireEvent.click(await screen.findByText("IP Spaces / Blocks"));
    expect(
      await screen.findByText(/don't have permission to see IP spaces/),
    ).toBeTruthy();
    expect(
      await screen.findByText(/don't have permission to see IP blocks/),
    ).toBeTruthy();
    expect(screen.queryByText("No linked spaces/blocks")).toBeNull();
  });

  it("lists the linked rows for a role that can read them", async () => {
    mode = "ok";
    show("/network/asns/a1", "/network/asns/:id", <AsnDetailPage />);
    fireEvent.click(await screen.findByText("IP Spaces / Blocks"));
    expect(await screen.findByText("our-space")).toBeTruthy();
    expect(await screen.findByText("our-block")).toBeTruthy();
  });
});

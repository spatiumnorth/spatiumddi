/**
 * @vitest-environment jsdom
 *
 * Six registries and a provider's Default ASN used to state an empty list, a
 * zero count or an unset value over a read the server refused (#2703). A page
 * whose read was refused says so; the empty copy stays over a read that
 * answered.
 */
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ComponentType } from "react";

let refused = true;
const asnList = vi.fn();

const deny = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "need 'read' on 'x'" } },
  });

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const lists = new Set([
    "avApi",
    "bacnetApi",
    "dicomApi",
    "otApi",
    "e911Api",
    "multicastApi",
    "ipamApi",
  ]);
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
                return () =>
                  Promise.resolve({ is_superadmin: false, grants: [] });
              if (name === "asnsApi" && method === "list") return asnList;
              if (name === "providersApi" && method === "list")
                return () =>
                  Promise.resolve({
                    total: 1,
                    items: [
                      {
                        id: "p1",
                        name: "Acme Transit",
                        kind: "transit",
                        default_asn_id: "a1",
                      },
                    ],
                  });
              if (lists.has(name))
                return () =>
                  refused
                    ? deny()
                    : Promise.resolve(
                        method === "listDomains" ||
                          method === "listZones" ||
                          method === "listBbmds" ||
                          method === "listPeers" ||
                          method === "listReservedRanges" ||
                          method === "listSubnets"
                          ? []
                          : { items: [], total: 0 },
                      );
              return () => new Promise(() => {});
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

const { E911Page } = await import("./E911Page");
const { AVFlowsPage } = await import("./AVFlowsPage");
const { BACnetDevicesPage } = await import("./BACnetDevicesPage");
const { DICOMPage } = await import("./DICOMPage");
const { OTDevicesPage } = await import("./OTDevicesPage");
const { MulticastDomainsTab } = await import("./MulticastDomainsPage");
const { ProvidersPage } = await import("./ProvidersPage");

beforeEach(() => {
  refused = true;
  asnList.mockReset();
  asnList.mockImplementation(deny);
});
afterEach(cleanup);

function show(Page: ComponentType) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Page />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const text = () => document.body.textContent ?? "";

const CASES: [string, ComponentType, string, RegExp[]][] = [
  ["E911", E911Page, "Emergency Response Locations", [/No Emergency Response/]],
  ["AV", AVFlowsPage, "AV flows", [/\b0 flows?\b/, /No AV flows recorded/]],
  [
    "BACnet",
    BACnetDevicesPage,
    "BACnet devices",
    [/\b0 devices?\b/, /No BACnet devices recorded/],
  ],
  [
    "DICOM",
    DICOMPage,
    "DICOM application entities",
    [/\b0 AEs?\b/, /No DICOM application entities recorded/],
  ],
  [
    "OT",
    OTDevicesPage,
    "OT devices",
    [/\b0 devices?\b/, /No subnet has been classified yet/],
  ],
  [
    "Multicast domains",
    MulticastDomainsTab,
    "PIM domains",
    [/No PIM domains yet/],
  ],
];

describe("registries over a refused read", () => {
  it.each(CASES)(
    "%s says it was refused",
    async (_n, Page, what, forbidden) => {
      show(Page);
      await waitFor(() =>
        expect(text()).toContain(`You don't have permission to see ${what}`),
      );
      for (const re of forbidden) expect(text()).not.toMatch(re);
    },
  );

  it.each(CASES)(
    "%s keeps its empty copy over an answered read",
    async (_n, Page, what, forbidden) => {
      refused = false;
      show(Page);
      await waitFor(() =>
        expect(text()).toMatch(forbidden[forbidden.length - 1]),
      );
      expect(text()).not.toContain(`You don't have permission to see ${what}`);
    },
  );
});

describe("Providers", () => {
  it("does not ask for ASNs it may not read and shows the Default ASN as hidden", async () => {
    show(ProvidersPage);
    await waitFor(() => expect(text()).toContain("Acme Transit"));
    expect(asnList).not.toHaveBeenCalled();
    expect(text()).toContain("set, hidden");
  });
});

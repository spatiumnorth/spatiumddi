/**
 * @vitest-environment jsdom
 *
 * Network Discovery's heading counted a refused device list as "0 devices" and
 * DICOM's associations section said "No associations documented." over a
 * refused read (#3797). A refused read is never drawn as zero or as none.
 */
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ComponentType } from "react";

let refused = true;

const deny = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "need 'read' on 'x'" } },
  });

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
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
              if (name === "networkApi" && method === "listDevices")
                return () =>
                  refused ? deny() : Promise.resolve({ items: [], total: 0 });
              if (name === "dicomApi")
                return () =>
                  refused
                    ? deny()
                    : Promise.resolve(
                        method === "listPeers" ? [] : { items: [], total: 0 },
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

const { NetworkPage } = await import("./NetworkPage");
const { DICOMPage } = await import("./DICOMPage");

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

describe("refused reads are not drawn as zero or none (#3797)", () => {
  it("Network Discovery withholds the device count", async () => {
    refused = true;
    show(NetworkPage);
    await waitFor(() =>
      expect(text()).toContain("You don't have permission to see network"),
    );
    expect(text()).not.toMatch(/0 devices/);
  });

  it("DICOM does not say no associations are documented", async () => {
    refused = true;
    show(DICOMPage);
    await waitFor(() =>
      expect(text()).toContain("You don't have permission to see associations"),
    );
    expect(text()).not.toContain("No associations documented");
  });

  it("an answered empty read still says so", async () => {
    refused = false;
    show(DICOMPage);
    await waitFor(() => expect(text()).toContain("No associations documented"));
  });
});

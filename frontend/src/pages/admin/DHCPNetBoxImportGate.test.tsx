/**
 * @vitest-environment jsdom
 *
 * The DHCP and NetBox importers start an import only for a superadmin, as
 * the DNS importer does (#1940, #2523): every route under their import
 * prefixes is superadmin-only, so a Viewer who fills in the form is not
 * offered a Preview import or Test connection that ends in a 403.
 *
 * (Header of the DNS sibling test follows.) The DNS import page starts an import only for a user the API will accept
 * (#1879's sweep). Every route under `/dns/import` — preview, test
 * connection and commit — takes a superadmin, so a DNS Editor holding
 * `admin` on every DNS resource was free to upload an archive or type in a
 * PowerDNS key and be refused at the end. Commit is reachable only from a
 * successful preview, so gating what starts one closes the path.
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const myPermissions = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  // Every API call a test does not answer stays pending.
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
                : name === "authApi" && method === "myPermissions"
                  ? () => myPermissions()
                  : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

import { DHCPImportPage } from "./DHCPImportPage";
import { NetBoxImportPage } from "./NetBoxImportPage";

const SUPERADMIN = "Requires superadmin";

function signInAs(kind: "viewer" | "superadmin") {
  myPermissions.mockResolvedValue(
    kind === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: [{ action: "read", resource_type: "*", resource_id: null }],
        },
  );
}

async function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {});
  await act(async () => {});
}

afterEach(() => {
  cleanup();
  myPermissions.mockReset();
});

describe("DHCP + NetBox import follow the API's superadmin gate", () => {
  it("refuses a Viewer Preview import on every DHCP tab", async () => {
    signInAs("viewer");
    await show(<DHCPImportPage />);
    for (const tab of [/^ISC DHCP/, /^Kea/, /^Windows DHCP/]) {
      fireEvent.click(screen.getByRole("button", { name: tab }));
      await act(async () => {});
      const b = screen.getByRole("button", { name: /Preview import/ });
      expect((b as HTMLButtonElement).disabled).toBe(true);
      expect(b.getAttribute("title")).toBe(SUPERADMIN);
    }
  });

  it("refuses a Viewer Test connection and Preview import on NetBox, form filled", async () => {
    signInAs("viewer");
    await show(<NetBoxImportPage />);
    fireEvent.change(
      screen.getByPlaceholderText("https://netbox.internal:8080"),
      {
        target: { value: "https://192.0.2.1" },
      },
    );
    fireEvent.change(screen.getByPlaceholderText("netbox api token"), {
      target: { value: "dummy" },
    });
    for (const name of [/Test connection/, /Preview import/]) {
      const b = screen.getByRole("button", { name }) as HTMLButtonElement;
      expect(b.disabled, String(name)).toBe(true);
      expect(b.title, String(name)).toBe(SUPERADMIN);
    }
  });

  it("does not hold a superadmin back: Test connection enables once filled", async () => {
    signInAs("superadmin");
    await show(<NetBoxImportPage />);
    fireEvent.change(
      screen.getByPlaceholderText("https://netbox.internal:8080"),
      {
        target: { value: "https://192.0.2.1" },
      },
    );
    fireEvent.change(screen.getByPlaceholderText("netbox api token"), {
      target: { value: "dummy" },
    });
    const b = screen.getByRole("button", {
      name: /Test connection/,
    }) as HTMLButtonElement;
    expect(b.disabled).toBe(false);
    expect(b.title).toBe("");
  });
});

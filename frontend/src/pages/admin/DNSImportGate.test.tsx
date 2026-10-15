/**
 * @vitest-environment jsdom
 *
 * The DNS import page starts an import only for a user the API will accept
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
  waitFor,
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

import { DNSImportPage } from "./DNSImportPage";

const SUPERADMIN = "Requires superadmin";
const DNS_EDITOR = [
  ["admin", "dns_group"],
  ["admin", "dns_zone"],
  ["admin", "dns_record"],
];

function signInAs(grants: string[][] | "superadmin") {
  myPermissions.mockResolvedValue(
    grants === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: grants.map(([action, resource_type]) => ({
            action,
            resource_type,
            resource_id: null,
          })),
        },
  );
}

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DNSImportPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(myPermissions).toHaveBeenCalled());
  await act(async () => {});
}

/** The controls that start an import, on every tab. */
async function startControls(): Promise<HTMLButtonElement[]> {
  const found: HTMLButtonElement[] = [];
  for (const tab of [
    /^BIND9/,
    /^Cloud/,
    /^PowerDNS/,
    /^Technitium/,
    /^Windows DNS/,
  ]) {
    fireEvent.click(screen.getByRole("button", { name: tab }));
    await act(async () => {});
    found.push(
      ...(screen.queryAllByRole("button", {
        name: /Preview import|Test connection/,
      }) as HTMLButtonElement[]),
    );
  }
  return found;
}

afterEach(() => {
  cleanup();
  myPermissions.mockReset();
});

describe("DNS import follows the API's superadmin gate", () => {
  it("refuses a DNS Editor every control that starts an import", async () => {
    signInAs(DNS_EDITOR);
    await show();
    const controls = await startControls();
    // 5 previews + PowerDNS and Technitium test connection.
    expect(controls).toHaveLength(7);
    for (const b of controls) {
      expect(b.disabled, b.textContent ?? "").toBe(true);
      expect(b.title, b.textContent ?? "").toBe(SUPERADMIN);
    }
  });

  it("does not hold a superadmin back with the reason", async () => {
    signInAs("superadmin");
    await show();
    const controls = await startControls();
    expect(controls).toHaveLength(7);
    // Still disabled until the form is filled in; the gate adds nothing.
    for (const b of controls) expect(b.title, b.textContent ?? "").toBe("");
  });
});

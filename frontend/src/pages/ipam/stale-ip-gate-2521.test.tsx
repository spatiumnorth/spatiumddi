/**
 * @vitest-environment jsdom
 *
 * The Stale IPs report offers Deprecate only to a user who may write
 * addresses, and says when the server refuses it (#2521).
 *
 * Both Deprecate actions were rendered for a read-only Viewer, and a refused
 * deprecate left the confirm dialog open with no word (the mutation had no
 * error handler). Real `usePermissions`, answered from
 * `GET /auth/me/permissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

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

const { StaleIPReportPage } = await import("./StaleIPReportPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const ENTRY = {
  id: "ip-1",
  address: "10.9.0.5",
  subnet_id: "sn-1",
  subnet_network: "10.9.0.0/24",
  space_id: "sp-1",
  hostname: "stale-host",
  status: "allocated",
  last_seen_at: null,
  last_seen_method: null,
  days_stale: null,
};

type Grants = [string, string][] | "superadmin";

async function open(grants: Grants, deprecate?: Answer) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
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
      ),
  };
  answers.ipamApi = {
    listSpaces: () => Promise.resolve([]),
    getStaleIPs: () => Promise.resolve({ total: 1, entries: [ENTRY] }),
    ...(deprecate ? { deprecateStaleIPs: deprecate } : {}),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <StaleIPReportPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("10.9.0.5");
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

const tick = () => fireEvent.click(screen.getByLabelText("Select 10.9.0.5"));

const deprecateAll = () =>
  screen.getByRole("button", { name: /Deprecate all 1/ }) as HTMLButtonElement;

describe("Stale IPs report (#2521)", () => {
  it("offers a read-only Viewer neither Deprecate action, and says why", async () => {
    await open([["read", "*"]]);
    const all = deprecateAll();
    expect(all.disabled).toBe(true);
    expect(all.title).toBe("Requires write permission on IPAM addresses");
    tick();
    const sel = screen.getByRole("button", {
      name: /Deprecate selected/,
    }) as HTMLButtonElement;
    expect(sel.disabled).toBe(true);
    expect(sel.title).toBe("Requires write permission on IPAM addresses");
  });

  it("offers a superadmin and an address writer both", async () => {
    await open("superadmin");
    expect(deprecateAll().disabled).toBe(false);
    cleanup();
    await open([
      ["read", "*"],
      ["write", "ip_address"],
    ]);
    expect(deprecateAll().disabled).toBe(false);
    tick();
    expect(
      (
        screen.getByRole("button", {
          name: /Deprecate selected/,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false);
  });

  it("says a refused deprecate was refused, in the dialog that stays open", async () => {
    const refusal = Object.assign(new Error("403"), {
      isAxiosError: true,
      response: {
        status: 403,
        data: {
          detail: "Permission denied: need 'write' on one of ['subnet']",
        },
      },
    });
    await open("superadmin", () => Promise.reject(refusal));
    fireEvent.click(deprecateAll());
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: /Deprecate all 1/ }),
    );
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toMatch(/Permission denied/);
    expect(screen.queryByRole("dialog")).not.toBeNull();
  });
});

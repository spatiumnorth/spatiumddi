/**
 * @vitest-environment jsdom
 *
 * #3466: the IP space, block and subnet dialogs and the subnet view for a
 * user holding only the built-in IPAM Editor role, which reads none of DNS
 * or DHCP. The dialogs' DNS tab asked GET /dns/groups (read on `dns_group`)
 * and each held group's zones (read on `dns_zone`), and said "No groups
 * configured." over a group the space holds; their DHCP tab asked
 * GET /dhcp/server-groups (read on `dhcp_server`); and the subnet view asked
 * its DHCP scopes (read on `dhcp_scope`) on every opening, which is the
 * refusal the issue saw when the IP detail opened from it. Each refusal is a
 * 403 and a denied audit row. None is asked now without its grant, and a
 * stored group or zone reads as linked but not shown.
 *
 * Every API call stays pending unless a test answers it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

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

const { EditSpaceModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

async function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

const SPACE = {
  id: "sp-1",
  name: "corp",
  description: "old",
  color: null,
  tags: {},
  dns_group_ids: ["g-1"],
  dns_zone_id: "z-1",
  dns_additional_zone_ids: ["z-2"],
  dhcp_server_group_id: "dg-1",
  vrf_id: null,
  asn_id: null,
  customer_id: null,
};

describe("IPAM DNS and DHCP sections with a failed permissions read (#3546)", () => {
  it("the DNS section says the permissions could not be read, not role wording, and asks no list", async () => {
    answer("authApi", "myPermissions", () =>
      Promise.reject(new Error("Network Error")),
    );
    const groups = vi.fn(() => Promise.resolve([]));
    answer("dnsApi", "listGroups", groups);
    answer("ipamApi", "getSpace", () => Promise.resolve(SPACE));
    await open(
      <EditSpaceModal
        space={SPACE as never}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    const sels = (await screen.findAllByTitle(
      /permissions could not be read/,
    )) as HTMLElement[];
    expect(sels.length).toBeGreaterThanOrEqual(3);
    for (const el of sels.filter((e) => e.tagName === "SELECT")) {
      expect((el as HTMLSelectElement).disabled).toBe(true);
      expect((el as HTMLSelectElement).selectedOptions[0].textContent).toMatch(
        /could not be read|None/,
      );
    }
    expect(document.body.textContent).toMatch(
      /1 linked \(Your permissions could not/,
    );
    expect(document.body.textContent).not.toMatch(/your role/i);
    expect(groups).not.toHaveBeenCalled();
  });

  it("the DHCP section says so too", async () => {
    answer("authApi", "myPermissions", () =>
      Promise.reject(new Error("Network Error")),
    );
    answer("ipamApi", "getSpace", () => Promise.resolve(SPACE));
    await open(
      <EditSpaceModal
        space={SPACE as never}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "DHCP" }));
    const sel = (await screen.findByTitle(
      /permissions could not be read/,
    )) as HTMLSelectElement;
    expect(sel.disabled).toBe(true);
    expect(sel.selectedOptions[0].textContent).toMatch(/could not be read/);
    expect(document.body.textContent).not.toMatch(/your role/i);
  });
});

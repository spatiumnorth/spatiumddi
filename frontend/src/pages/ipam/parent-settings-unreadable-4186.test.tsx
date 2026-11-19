/**
 * @vitest-environment jsdom
 *
 * Edit Block / Edit Subnet read the parent's effective DNS and DHCP. A scoped
 * grant is refused that read, and the dialog said "No ... configured in parent
 * chain." as if the read had answered empty (#4186). It says the parent's
 * settings are not visible to the role; an answered empty read still says none.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}
const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      isAxiosError: true,
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

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
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function grants(list: Array<[string, string, string | null]>) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({
      is_superadmin: false,
      grants: list.map(([action, resource_type, resource_id]) => ({
        action,
        resource_type,
        resource_id,
      })),
    }),
  );
}

const { EditBlockModal } = await import("./IPAMPage");

const block = {
  id: "b-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.98.0.0/16",
  name: "top",
  dns_inherit_settings: true,
  dhcp_inherit_settings: true,
  dns_group_ids: [],
  dns_zone_id: null,
  dns_additional_zone_ids: [],
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 65536,
} as never;

async function openTab(tab: "DNS" | "DHCP") {
  grants([["write", "ip_block", "b-1"]]);
  answer("ipamApi", "getBlock", () => Promise.resolve(block));
  open(<EditBlockModal block={block} onClose={() => {}} />);
  fireEvent.click(await screen.findByRole("button", { name: tab }));
}

describe("Edit Block with the parent's settings refused (#4186)", () => {
  it("DNS tab says the parent's settings are not visible", async () => {
    answer("ipamApi", "getEffectiveSpaceDns", refused);
    await openTab("DNS");
    expect(
      await screen.findByText(/DNS settings are not visible to your role/),
    ).toBeTruthy();
    expect(screen.queryByText(/No DNS settings configured/)).toBeNull();
  });

  it("DHCP tab says the parent's settings are not visible", async () => {
    answer("ipamApi", "getEffectiveSpaceDhcp", refused);
    await openTab("DHCP");
    expect(
      await screen.findByText(/DHCP settings are not visible to your role/),
    ).toBeTruthy();
    expect(screen.queryByText(/No DHCP group configured/)).toBeNull();
  });

  it("an answered empty read still says none configured", async () => {
    answer("ipamApi", "getEffectiveSpaceDns", () =>
      Promise.resolve({
        dns_group_ids: [],
        dns_zone_id: null,
        dns_additional_zone_ids: [],
        inherited_from_block_id: null,
      }),
    );
    await openTab("DNS");
    expect(
      await screen.findByText("No DNS settings configured in parent chain."),
    ).toBeTruthy();
  });
});

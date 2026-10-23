/**
 * @vitest-environment jsdom
 *
 * A holder whose grant names ONE subnet can reach it in the console (#2569,
 * the console half of #2438).
 *
 * The API lets `{read, subnet, X}` + `{write, subnet, X}` through to X's own
 * routes while `GET /ipam/spaces` and `/blocks` stay 403 for that holder. The
 * console used to wait for those lists before opening `?subnet=X`, and asked
 * "write on subnets" with no id for Edit, which a scoped grant never matches.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Subnet } from "@/lib/api";

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
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { IPAMPage, SubnetDetail } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
  sessionStorage.clear();
});

const subnet = {
  id: "sub-x",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.77.1.0/24",
  name: "team-lab",
  total_ips: 254,
  allocated_ips: 0,
  utilization_percent: 0,
  dns_group_ids: [],
} as unknown as Subnet;

const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

function grantsOn(resourceId: string) {
  return () =>
    Promise.resolve({
      is_superadmin: false,
      grants: [
        { action: "read", resource_type: "subnet", resource_id: resourceId },
        { action: "write", resource_type: "subnet", resource_id: resourceId },
      ],
    });
}

function mount(ui: React.ReactNode, url = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("a grant scoped to one subnet", () => {
  it("opens /ipam?subnet=X although spaces and blocks are refused, with Edit enabled", async () => {
    answers.authApi = { myPermissions: grantsOn("sub-x") };
    answers.ipamApi = {
      listSpaces: refused,
      listBlocks: refused,
      listSubnets: () => Promise.resolve([subnet]),
      getSubnet: () => Promise.resolve(subnet),
      listAddresses: () => Promise.resolve([]),
    };
    answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
    mount(<IPAMPage />, "/ipam?subnet=sub-x");

    const edit = (await screen.findByRole("button", {
      name: "Edit",
    })) as HTMLButtonElement;
    await waitFor(() => expect(edit.disabled).toBe(false));
    expect(screen.queryByText(/Select a space, block, or subnet/)).toBeNull();
  });

  it("keeps Edit disabled when the grant names a different subnet", async () => {
    answers.authApi = { myPermissions: grantsOn("sub-other") };
    answers.ipamApi = {
      listAddresses: () => Promise.resolve([]),
    };
    answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
    mount(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);

    const edit = (await screen.findByRole("button", {
      name: "Edit",
    })) as HTMLButtonElement;
    // Let the permissions query settle before judging a fail-closed button.
    await new Promise((r) => setTimeout(r, 50));
    expect(edit.disabled).toBe(true);
  });
});

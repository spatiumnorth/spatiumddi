/**
 * @vitest-environment jsdom
 *
 * Address writes that move a subnet's count refetch the subnet AND block
 * lists (#3325): the server recounts the block chain in the same request, so
 * the parent block's Used figure must follow without a reload. Covers the
 * Edit address dialog (a status change) and a DHCP static's Save (its IPAM
 * mirror counts toward the subnet).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { DHCPScope, DHCPStaticAssignment, IPAddress } from "@/lib/api";

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

const { EditAddressModal } = await import("@/pages/ipam/IPAMPage");
const { CreateStaticAssignmentModal } =
  await import("@/pages/dhcp/CreateStaticAssignmentModal");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode, qc: QueryClient) {
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const invalidated = (spy: { mock: { calls: unknown[][] } }) =>
  spy.mock.calls.map((c) => (c[0] as { queryKey?: unknown })?.queryKey);

describe("address writes refetch the block list (#3325)", () => {
  it("Edit address Save", async () => {
    const addr = {
      id: "a-1",
      subnet_id: "sn-1",
      address: "10.0.0.5",
      hostname: "host-a",
      description: "",
      mac_address: null,
      status: "allocated",
      custom_fields: {},
      tags: {},
    } as unknown as IPAddress;
    answers.ipamApi = {
      getAddress: () => Promise.resolve(addr),
      updateAddress: () => Promise.resolve({ ...addr, hostname: "host-b" }),
    };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const spy = vi.spyOn(qc, "invalidateQueries");
    open(<EditAddressModal address={addr} onClose={() => {}} />, qc);
    const box = await screen.findByDisplayValue("host-a");
    fireEvent.change(box, { target: { value: "host-b" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(invalidated(spy)).toContainEqual(["blocks"]));
    expect(invalidated(spy)).toContainEqual(["subnets"]);
  });

  it("DHCP static Save", async () => {
    const scope = { id: "sc-1", subnet_id: "sn-1" } as DHCPScope;
    const row = {
      id: "st-1",
      scope_id: "sc-1",
      mac_address: "02:98:14:00:00:20",
      ip_address: "10.98.140.20",
      hostname: "xp-st-a",
      description: "",
      client_id: null,
    } as unknown as DHCPStaticAssignment;
    answers.dhcpApi = {
      listStatics: () => Promise.resolve([row]),
      listPools: () => Promise.resolve([]),
      updateStatic: () => Promise.resolve({ ...row, hostname: "xp-st-b" }),
    };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    qc.setQueryDefaults(["dhcp-statics"], {
      queryFn: () => answers.dhcpApi.listStatics(),
    });
    qc.setQueryData(["dhcp-statics", "sc-1"], [row]);
    const spy = vi.spyOn(qc, "invalidateQueries");
    open(
      <CreateStaticAssignmentModal
        scope={scope}
        staticAssignment={row}
        onClose={() => {}}
      />,
      qc,
    );
    const box = await screen.findByDisplayValue("xp-st-a");
    fireEvent.change(box, { target: { value: "xp-st-b" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(invalidated(spy)).toContainEqual(["blocks"]));
    expect(invalidated(spy)).toContainEqual(["subnets"]);
  });
});

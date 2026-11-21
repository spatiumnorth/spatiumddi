/**
 * @vitest-environment jsdom
 *
 * A DHCPv6 reservation can be keyed on a DUID with no MAC, from the DHCP
 * dialog and from IPAM (#3900).
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
import type { DHCPScope } from "@/lib/api";

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

const { CreateStaticAssignmentModal } =
  await import("@/pages/dhcp/CreateStaticAssignmentModal");
const { AddAddressModal } = await import("@/pages/ipam/IPAMPage");

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

const DUID = "00:01:00:01:2a:3b:4c:5d:aa:bb:cc:dd:ee:ff";

function control(label: string): HTMLInputElement {
  return screen.getByText(label, { selector: "label" })
    .nextElementSibling as HTMLInputElement;
}

describe("DHCP static dialog (#3900)", () => {
  const scope6 = {
    id: "sc-6",
    subnet_id: "sn-6",
    address_family: "ipv6",
  } as DHCPScope;
  const scope4 = { ...scope6, address_family: "ipv4" } as DHCPScope;

  function setup() {
    const createStatic = vi.fn((..._a: unknown[]) => Promise.resolve({}));
    answers.dhcpApi = {
      listPools: () => Promise.resolve([]),
      createStatic,
    };
    return createStatic;
  }

  it("creates a v6 reservation from a DUID alone, with the MAC sent as null", async () => {
    const createStatic = setup();
    open(<CreateStaticAssignmentModal scope={scope6} onClose={() => {}} />);
    const save = screen.getByRole("button", { name: /^Save|^Create/ });
    // No identifier yet: the form refuses to submit.
    expect((save as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(control("IP Address"), {
      target: { value: "2a11:6c7:1100:6e84::45" },
    });
    fireEvent.change(control("DUID"), { target: { value: DUID } });
    expect(control("MAC Address").required).toBe(false);
    await waitFor(() =>
      expect((save as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(save);
    await waitFor(() => expect(createStatic).toHaveBeenCalled());
    expect(createStatic.mock.calls[0][1]).toMatchObject({
      mac_address: null,
      duid: DUID,
      ip_address: "2a11:6c7:1100:6e84::45",
    });
  });

  it("still requires a MAC on a v4 scope and offers no DUID", () => {
    setup();
    open(<CreateStaticAssignmentModal scope={scope4} onClose={() => {}} />);
    expect(control("MAC Address").required).toBe(true);
    expect(screen.queryByText("DUID", { selector: "label" })).toBeNull();
  });
});

describe("IPAM Add address (#3900)", () => {
  function allocate(network: string) {
    answers.customFieldsApi = { list: () => Promise.resolve([]) };
    answers.ipamApi = {
      previewNextIp: () =>
        Promise.resolve({
          address: "2a11:6c7:1100:6e84::45",
          strategy: "sequential",
        }),
      getSubnet: () => Promise.resolve({ id: "sub-1", network }),
    };
    const nextAddress = vi.fn((..._a: unknown[]) =>
      Promise.resolve({ id: "ip-new" }),
    );
    answers.ipamApi.nextAddress = nextAddress;
    open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />);
    return nextAddress;
  }

  it("offers a DUID for a static_dhcp row on an IPv6 subnet and sends it", async () => {
    const nextAddress = allocate("2a11:6c7:1100:6e84::/64");
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "archibald-pc" },
    });
    const status = screen.getByText("Type / Status", { selector: "label" })
      .nextElementSibling as HTMLSelectElement;
    fireEvent.change(status, { target: { value: "static_dhcp" } });
    const duid = await screen.findByPlaceholderText(/00:01:00:01/);
    fireEvent.change(duid, { target: { value: DUID } });
    const button = screen.getByRole("button", { name: "Allocate" });
    await waitFor(() =>
      expect((button as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(button);
    await waitFor(() => expect(nextAddress).toHaveBeenCalled());
    expect(nextAddress.mock.calls[0][1]).toMatchObject({
      status: "static_dhcp",
      duid: DUID,
    });
  });

  it("offers no DUID on an IPv4 subnet", async () => {
    allocate("172.16.10.0/24");
    const status = screen.getByText("Type / Status", { selector: "label" })
      .nextElementSibling as HTMLSelectElement;
    fireEvent.change(status, { target: { value: "static_dhcp" } });
    await waitFor(() => expect(status.value).toBe("static_dhcp"));
    expect(screen.queryByPlaceholderText(/00:01:00:01/)).toBeNull();
  });
});

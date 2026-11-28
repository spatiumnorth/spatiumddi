/**
 * @vitest-environment jsdom
 *
 * The choices the multicast, AV range, OT zone, OT descriptor and BACnet
 * dialogs fill from IPAM (#4635). A role refused the IP space, subnet or
 * address list used to get an empty choice with no word why; each now says the
 * list is not visible to it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const refused = () =>
  Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: { status: 403, data: { detail: "Permission denied" } },
  });
const searchAnswer = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const stub = (name: string, extra: Record<string, unknown>) =>
    new Proxy(
      { ...(actual as Record<string, any>)[name], ...extra },
      {
        get: (t, m) =>
          m in t
            ? t[m as string]
            : typeof m === "symbol"
              ? undefined
              : async () => [],
      },
    );
  return {
    ...actual,
    ipamApi: stub("ipamApi", {
      listSpaces: async () => Promise.reject(refused()),
      listSubnets: async () => Promise.reject(refused()),
    }),
    searchApi: stub("searchApi", {
      search: (...a: unknown[]) => searchAnswer(...a),
    }),
  };
});

const { IPAddressPicker } = await import("@/components/IPAddressPicker");
const { MulticastGroupModal } = await import("./MulticastGroupsPage");
const { RangeModal } = await import("./AVFlowsPage");
const { ZoneModal } = await import("./OTDevicesPage");

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  searchAnswer.mockReset();
});

describe("refused IPAM pickers (#4635)", () => {
  it("multicast group dialog says the IP space list is refused", async () => {
    wrap(
      <MulticastGroupModal
        existing={null}
        spaces={[]}
        spacesError={refused()}
        onClose={() => {}}
      />,
    );
    expect(
      await screen.findByText(/don't have permission to see IP spaces/i),
    ).toBeTruthy();
  });

  it("AV range dialog says the IP space list is refused", async () => {
    wrap(
      <RangeModal
        mode="create"
        range={null}
        protocols={[]}
        onClose={() => {}}
      />,
    );
    expect(
      await screen.findByText(/don't have permission to see IP spaces/i),
    ).toBeTruthy();
  });

  it("OT zone dialog says the subnet list is refused", async () => {
    wrap(<ZoneModal mode="create" zone={null} onClose={() => {}} />);
    expect(
      await screen.findByText(/don't have permission to see subnets/i),
    ).toBeTruthy();
  });

  it("address picker says so when search leaves out IP addresses", async () => {
    searchAnswer.mockResolvedValue({
      query: "10.0.0.7",
      total: 0,
      results: [],
      searched_types: [{ type: "device", label: "Devices", group: "network" }],
    });
    wrap(<IPAddressPicker value={null} onChange={() => {}} />);
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "10.0.0.7" },
    });
    expect(
      await screen.findByText(/don't have permission to see IP addresses/i),
    ).toBeTruthy();
    expect(screen.queryByText(/No IPs match/)).toBeNull();
  });

  it("address picker still says No IPs match when addresses were searched", async () => {
    searchAnswer.mockResolvedValue({
      query: "10.0.0.7",
      total: 0,
      results: [],
      searched_types: [
        { type: "ip_address", label: "IP addresses", group: "ipam" },
      ],
    });
    wrap(<IPAddressPicker value={null} onChange={() => {}} />);
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "10.0.0.7" },
    });
    expect(await screen.findByText(/No IPs match/)).toBeTruthy();
  });

  it("address picker names a refused search", async () => {
    searchAnswer.mockRejectedValue(refused());
    wrap(<IPAddressPicker value={null} onChange={() => {}} />);
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "10.0.0.7" },
    });
    expect(
      await screen.findByText(/don't have permission to see IP addresses/i),
    ).toBeTruthy();
  });
});

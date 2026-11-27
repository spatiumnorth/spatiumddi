/**
 * @vitest-environment jsdom
 *
 * #4893 — for a role that may write one zone but not read the group's zones,
 * Edit IP Address named the writable zone as the address's DNS Zone when the
 * record sits in another zone. The dialog must show the record's real zone,
 * or say that zone is not visible to the role.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress } from "@/lib/api";

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

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const WRITABLE = { id: "z-w", name: "zw.example.", kind: "forward" };

function setup() {
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
    forward_zone_id: "z-x",
  } as unknown as IPAddress;
  const forbidden = () => Promise.reject({ response: { status: 403 } });
  answers.ipamApi = {
    getEffectiveSubnetDns: () =>
      Promise.resolve({ dns_group_ids: ["g-1"], dns_additional_zone_ids: [] }),
    getAddress: () => Promise.resolve(addr),
    listAliases: () => Promise.resolve([]),
  };
  answers.dnsApi = {
    // The role may write zw only: the group list is refused, the
    // subnet-scoped fallback answers with the writable zone.
    listZones: () => Promise.resolve([WRITABLE]),
    listGroups: forbidden,
  };
  answers.customFieldsApi = { list: () => Promise.resolve([]) };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EditAddressModal address={addr} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Edit address keeps the record's own zone (#4893)", () => {
  it("does not name the writable zone as the stored zone", async () => {
    setup();
    await waitFor(() =>
      expect(screen.getByText(/not visible to your role/)).toBeTruthy(),
    );
    const sel = screen
      .getAllByRole("combobox")
      .find((s) => (s as HTMLSelectElement).value === "z-x");
    expect(sel).toBeTruthy();
  });
});

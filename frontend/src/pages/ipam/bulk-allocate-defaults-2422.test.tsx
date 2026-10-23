/**
 * @vitest-environment jsdom
 *
 * Bulk allocate's untouched range lies inside the subnet (#2422): a /29 ends
 * at .7, so "network + 10 .. network + 20" was refused on Preview.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { Subnet } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  ipamApi: {
    getEffectiveSubnetDns: () => Promise.resolve({ dns_group_ids: [] }),
  },
  dnsApi: { listZones: () => Promise.resolve([]) },
}));
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

const { BulkAllocateModal } = await import("./BulkAllocateModal");

afterEach(cleanup);

function range(network: string): [string, string] {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <BulkAllocateModal
        subnet={{ id: "s", network, name: "x" } as Subnet}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
  const val = (label: string) =>
    (
      screen.getByText(label, { selector: "label" })
        .nextElementSibling as HTMLInputElement
    ).value;
  return [val("Range start"), val("Range end")];
}

describe("Bulk allocate default range (#2422)", () => {
  it("a /29 opens on its first and last usable addresses", () => {
    expect(range("10.220.3.0/29")).toEqual(["10.220.3.1", "10.220.3.6"]);
  });
  it("a /28 clamps the end to its last usable address", () => {
    expect(range("10.220.3.16/28")).toEqual(["10.220.3.26", "10.220.3.30"]);
  });
  it("a /24 keeps the usual 10..20", () => {
    expect(range("192.168.0.0/24")).toEqual(["192.168.0.10", "192.168.0.20"]);
  });
  it("a /27 keeps 10..20 (still inside)", () => {
    expect(range("10.0.0.0/27")).toEqual(["10.0.0.10", "10.0.0.20"]);
  });
  it("a /126 IPv6 stays inside the subnet", () => {
    const [s, e] = range("2001:db8::/126");
    expect(s).toBe("2001:0db8:0000:0000:0000:0000:0000:0001");
    expect(e).toBe("2001:0db8:0000:0000:0000:0000:0000:0003");
  });
});

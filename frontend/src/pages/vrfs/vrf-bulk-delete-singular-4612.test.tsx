/**
 * @vitest-environment jsdom
 *
 * One VRF holding one space reads in the singular (#4612).
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { VRF } from "@/lib/api";
import { BulkDeleteModal } from "./VRFsPage";

const vrf = (over: Partial<VRF>): VRF => ({
  id: "v1",
  name: "red",
  description: "",
  asn_id: null,
  route_distinguisher: null,
  import_targets: [],
  export_targets: [],
  tags: {},
  custom_fields: {},
  customer_id: null,
  created_at: "",
  modified_at: "",
  space_count: 1,
  block_count: 1,
  ...over,
});

afterEach(cleanup);

describe("VRF bulk delete dialog", () => {
  it("uses the singular for one VRF, one space, one block", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <BulkDeleteModal rows={[vrf({})]} onClose={() => {}} />
      </QueryClientProvider>,
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("Delete 1 VRF?");
    expect(text).toContain("1 space · 1 block");
    expect(text).not.toContain("1 VRFs");
    expect(text).not.toContain("1 spaces");
  });

  it("keeps the plural for two", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <BulkDeleteModal
          rows={[
            vrf({ space_count: 2, block_count: 0 }),
            vrf({ id: "v2", name: "blue" }),
          ]}
          onClose={() => {}}
        />
      </QueryClientProvider>,
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("Delete 2 VRFs?");
    expect(text).toContain("2 spaces · 0 blocks");
  });
});

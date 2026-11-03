/**
 * @vitest-environment jsdom
 *
 * #3381: the dynamic-updates ACL save carries the version it read. A 409
 * says someone else changed the ACL and offers Reload; a successful save
 * hands back the new version for the next save in the same dialog.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

const getAcl = vi.fn();
const replaceAcl = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      getZoneUpdateAcl: (...a: unknown[]) => getAcl(...a),
      replaceZoneUpdateAcl: (...a: unknown[]) => replaceAcl(...a),
      listTSIGKeys: () => Promise.resolve([]),
    },
  };
});

import { DynamicUpdateAclModal } from "./DynamicUpdateAclModal";

const caps = {
  supports_ip_acl: true,
  supports_tsig_acl: true,
  supports_name_scoping: false,
  supports_per_type: false,
  coarse_enum_only: false,
  supported: true,
};
const acl = (version: string, cidr: string) => ({
  zone_id: "z1",
  version,
  dynamic_update_enabled: true,
  driver_names: ["bind9"],
  caps,
  entries: [
    {
      id: "e1",
      seq: 0,
      action: "grant",
      match_kind: "ip",
      ip_cidr: cidr,
      tsig_key_id: null,
      tsig_key_name: null,
      name_scope: null,
      name_pattern: null,
      record_types: null,
    },
  ],
  warnings: [],
});

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DynamicUpdateAclModal
        groupId="g1"
        zoneId="z1"
        zoneName="a.example.com."
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("ACL version check (#3381)", () => {
  it("sends the token it read, then the new one on a second save", async () => {
    getAcl.mockResolvedValue(acl("v1", "10.0.0.1/32"));
    replaceAcl.mockResolvedValueOnce(acl("v2", "10.0.0.1/32"));
    replaceAcl.mockResolvedValueOnce(acl("v3", "10.0.0.1/32"));
    mount();
    const save = await screen.findByRole("button", { name: "Save ACL" });
    await userEvent.click(save);
    await waitFor(() => expect(replaceAcl).toHaveBeenCalledTimes(1));
    expect(replaceAcl.mock.calls[0][2].expected_version).toBe("v1");
    await waitFor(() =>
      expect((save as HTMLButtonElement).disabled).toBe(false),
    );
    await userEvent.click(save);
    await waitFor(() => expect(replaceAcl).toHaveBeenCalledTimes(2));
    expect(replaceAcl.mock.calls[1][2].expected_version).toBe("v2");
  });

  it("a 409 shows the message and Reload re-reads, staying open", async () => {
    getAcl.mockResolvedValueOnce(acl("v1", "10.0.0.1/32"));
    getAcl.mockResolvedValue(acl("v9", "10.9.9.9/32"));
    replaceAcl.mockRejectedValueOnce({
      response: {
        status: 409,
        data: { detail: { code: "ACL_VERSION_CONFLICT", message: "x" } },
      },
    });
    mount();
    await userEvent.click(
      await screen.findByRole("button", { name: "Save ACL" }),
    );
    expect(
      await screen.findByText(/Someone changed this ACL since you opened it/),
    ).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Reload" }));
    await waitFor(() => expect(getAcl).toHaveBeenCalledTimes(2));
    expect(await screen.findByDisplayValue("10.9.9.9/32")).toBeTruthy();
    expect(screen.queryByText(/Someone changed this ACL/)).toBeNull();
    expect(screen.getByRole("button", { name: "Save ACL" })).toBeTruthy();
  });
});

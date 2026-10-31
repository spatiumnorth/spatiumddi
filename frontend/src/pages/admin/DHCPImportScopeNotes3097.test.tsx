/**
 * @vitest-environment jsdom
 *
 * #3097: a scope's own warnings (a pool left out of the import and why) were
 * shown only as a count. The review table lists their text.
 */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { DHCPImportPreview } from "@/lib/api";
import { PreviewPanel } from "./DHCPImportPage";

const NOTE =
  "Pool '10.221.99.10-10.221.99.20' not imported: outside 10.221.13.0/24.";

function preview(notes: string[]): DHCPImportPreview {
  return {
    source: "kea",
    scopes: [
      {
        subnet_cidr: "10.221.13.0/24",
        address_family: "ipv4",
        name: "",
        description: "",
        lease_time: 3600,
        min_lease_time: null,
        max_lease_time: null,
        is_active: true,
        options: {},
        pools: [],
        reservations: [],
        ddns_enabled: false,
        ddns_hostname_policy: "",
        v6_address_mode: "",
        skipped_options: {},
        ha_info: null,
        parse_warnings: notes,
      },
    ],
    client_classes: [],
    conflicts: [],
    warnings: [],
    unsupported: [],
    total_pools: 0,
    total_reservations: 0,
    address_family_histogram: {},
  };
}

function show(p: DHCPImportPreview) {
  render(
    <PreviewPanel
      preview={p}
      decisions={{}}
      setDecisions={vi.fn()}
      conflictByCidr={new Map()}
      canCreateSubnets={false}
      onCommit={vi.fn()}
      committing={false}
      onReset={vi.fn()}
    />,
  );
}

afterEach(cleanup);

describe("DHCP import preview scope notes", () => {
  it("shows the text of a scope's note", () => {
    show(preview([NOTE]));
    expect(screen.getByText(NOTE)).toBeTruthy();
  });

  it("renders a note taken from the source file as text, not markup", () => {
    const hostile =
      "Pool '<img src=x onerror=alert(1)>' not imported: not a valid address range.";
    show(preview([hostile]));
    expect(screen.getByText(hostile)).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("shows no notes list for a scope without notes", () => {
    show(preview([]));
    expect(screen.queryByRole("list")).toBeNull();
  });
});

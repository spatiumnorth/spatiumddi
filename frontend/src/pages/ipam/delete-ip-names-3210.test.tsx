/**
 * @vitest-environment jsdom
 *
 * The Delete IP Address dialogs name the host and its DNS records (#3210).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress } from "@/lib/api";

const listAliases = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    ipamApi: {
      ...actual.ipamApi,
      listAliases: (...a: unknown[]) => listAliases(...a),
    },
  };
});

import { BulkDeleteAddressesModal, DeleteOrOrphanModal } from "./IPAMPage";

afterEach(() => {
  cleanup();
  listAliases.mockReset();
});

function show(addr: Partial<IPAddress>) {
  const address = {
    id: "ip-1",
    address: "192.168.0.22",
    status: "allocated",
    ...addr,
  } as IPAddress;
  const qc = new QueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DeleteOrOrphanModal
          address={address}
          onOrphan={() => {}}
          onPurge={() => {}}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const flat = (el: HTMLElement) => el.textContent!.replace(/\s+/g, " ");

describe("Delete IP Address names the host and records (#3210)", () => {
  it("names the FQDN beside the IP in the question", async () => {
    listAliases.mockResolvedValue([]);
    show({ fqdn: "printer-3.corp.example.com", hostname: "printer-3" });
    expect(
      screen
        .getByText(/What should happen to/)
        .textContent!.replace(/\s+/g, " "),
    ).toBe("What should happen to 192.168.0.22 (printer-3.corp.example.com)?");
  });

  it("lists the primary record and aliases in both panels", async () => {
    listAliases.mockResolvedValue([
      {
        id: "a",
        name: "p3",
        record_type: "CNAME",
        value: "",
        zone_id: "",
        fqdn: "",
      },
    ]);
    show({
      hostname: "printer-3",
      fqdn: "printer-3.corp.example.com",
      dns_record_id: "r1",
      alias_count: 1,
    });
    await waitFor(() =>
      expect(screen.getAllByText("p3 CNAME")).toHaveLength(2),
    );
    expect(screen.getAllByText("printer-3.corp.example.com A")).toHaveLength(2);
  });

  it("caps a long list", async () => {
    listAliases.mockResolvedValue(
      Array.from({ length: 8 }, (_, i) => ({
        id: `${i}`,
        name: `n${i}`,
        record_type: "CNAME",
        value: "",
        zone_id: "",
        fqdn: "",
      })),
    );
    show({ alias_count: 8 });
    await waitFor(() =>
      expect(screen.getAllByText(/and 3 more/)).toHaveLength(2),
    );
  });

  it("keeps today's wording with no hostname and no records", async () => {
    show({ alias_count: 0 });
    const q = screen.getByText(/What should happen to/);
    expect(flat(q)).toBe("What should happen to 192.168.0.22?");
    expect(screen.queryByText(/DNS records:/)).toBeNull();
    expect(listAliases).not.toHaveBeenCalled();
  });

  it("still works and says so when the aliases cannot be read", async () => {
    listAliases.mockRejectedValue({ response: { status: 403, data: {} } });
    show({ alias_count: 2, hostname: "h" });
    await waitFor(() =>
      expect(screen.getAllByText(/don't have permission to see/)).toHaveLength(
        2,
      ),
    );
    expect(screen.getByText("Delete Permanently")).toBeTruthy();
    expect(screen.getByText("Mark as Orphan")).toBeTruthy();
  });
});

describe("Bulk delete names the selected hosts (#3210)", () => {
  it("lists each address with its host, capped", () => {
    const rows = Array.from({ length: 7 }, (_, i) => ({
      id: `i${i}`,
      address: `10.0.0.${i + 1}`,
      hostname: `h${i}`,
      fqdn: null,
    }));
    render(
      <QueryClientProvider client={new QueryClient()}>
        <BulkDeleteAddressesModal
          ipIds={rows.map((r) => r.id)}
          addresses={rows}
          onClose={() => {}}
          onDone={() => {}}
        />
      </QueryClientProvider>,
    );
    expect(screen.getByText("10.0.0.1")).toBeTruthy();
    expect(screen.getByText(/\(h0\)/)).toBeTruthy();
    expect(screen.getByText("and 2 more")).toBeTruthy();
    expect(screen.queryByText("10.0.0.6")).toBeNull();
  });
});

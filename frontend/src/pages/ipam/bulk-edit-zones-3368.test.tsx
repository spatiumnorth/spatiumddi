/**
 * @vitest-environment jsdom
 *
 * Bulk edit's DNS Zone re-reads the subnet's DNS settings every time it
 * opens, as Allocate IP does since #3078: a primary zone moved by Edit Block
 * within the cache window is the one marked and offered (#3368).
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
import type { DNSZone } from "@/lib/api";

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

const { BulkEditAddressesModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const zone = (id: string, name: string) =>
  ({ id, group_id: "g1", name, kind: "forward" }) as DNSZone;

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

describe("Bulk edit DNS Zone (#3368)", () => {
  it("offers the block's new primary zone although the old answer is cached", async () => {
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: "zb",
        dns_additional_zone_ids: [],
      }),
    );
    answer("dnsApi", "listZones", () =>
      Promise.resolve([zone("za", "a.example."), zone("zb", "b.example.")]),
    );
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    const bulkEdit = vi.fn(() =>
      Promise.resolve({ updated_count: 2, skipped: [] }),
    );
    answer("ipamApi", "bulkEditAddresses", bulkEdit);

    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    // What Allocate IP read before Edit Block moved the zone, seconds ago.
    qc.setQueryData(["effective-dns-subnet", "s1"], {
      dns_group_ids: ["g1"],
      dns_zone_id: "za",
      dns_additional_zone_ids: [],
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <BulkEditAddressesModal
            ipIds={["i1", "i2"]}
            subnetId="s1"
            onClose={() => {}}
            onDone={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByLabelText("DNS Zone"));
    const zoneSelect = () =>
      [...document.querySelectorAll("select")].find((el) =>
        [...el.options].some((o) => o.value === "za" || o.value === "zb"),
      ) as HTMLSelectElement;
    await waitFor(() => expect(zoneSelect()).toBeTruthy());
    const select = zoneSelect();
    await waitFor(() => {
      const values = [...(select as HTMLSelectElement).options].map(
        (o) => o.value,
      );
      expect(values).toContain("zb");
      expect((select as HTMLSelectElement).value).toBe("zb");
    });
    const apply = screen.getByRole("button", { name: "Apply to all" });
    await waitFor(() =>
      expect((apply as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(apply);
    await waitFor(() => expect(bulkEdit).toHaveBeenCalled());
    expect((bulkEdit.mock.calls[0] as unknown[])[0]).toMatchObject({
      changes: { dns_zone_id: "zb" },
    });
  });

  function mount(cached: unknown) {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    qc.setQueryData(["effective-dns-subnet", "s1"], cached);
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <BulkEditAddressesModal
            ipIds={["i1", "i2"]}
            subnetId="s1"
            onClose={() => {}}
            onDone={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }
  const cachedA = {
    dns_group_ids: ["g1"],
    dns_zone_id: "za",
    dns_additional_zone_ids: [],
  };
  function common() {
    answer("dnsApi", "listZones", () =>
      Promise.resolve([zone("za", "a.example."), zone("zb", "b.example.")]),
    );
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    const bulkEdit = vi.fn(() =>
      Promise.resolve({ updated_count: 2, skipped: [] }),
    );
    answer("ipamApi", "bulkEditAddresses", bulkEdit);
    return bulkEdit;
  }

  it("holds Apply and the picker while the re-read is in flight", async () => {
    common();
    let release: (v: unknown) => void = () => {};
    answer(
      "ipamApi",
      "getEffectiveSubnetDns",
      () => new Promise((r) => (release = r)),
    );
    mount(cachedA);
    fireEvent.click(await screen.findByLabelText("DNS Zone"));
    const apply = screen.getByRole("button", { name: "Apply to all" });
    await waitFor(() =>
      expect(screen.getByText(/Re-reading the subnet/)).toBeTruthy(),
    );
    expect((apply as HTMLButtonElement).disabled).toBe(true);
    const select = [...document.querySelectorAll("select")].find((el) =>
      [...el.options].some((o) => o.value === "za"),
    ) as HTMLSelectElement;
    expect(select.disabled).toBe(true);
    release({ ...cachedA, dns_zone_id: "zb" });
    await waitFor(() =>
      expect((apply as HTMLButtonElement).disabled).toBe(false),
    );
    expect(screen.queryByText(/Re-reading the subnet/)).toBeNull();
  });

  it("a failed re-read keeps the earlier answer, says so, and does not block Apply", async () => {
    const bulkEdit = common();
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.reject(new Error("offline")),
    );
    mount(cachedA);
    fireEvent.click(await screen.findByLabelText("DNS Zone"));
    await waitFor(() =>
      expect(screen.getByText(/Could not re-read the subnet/)).toBeTruthy(),
    );
    const apply = screen.getByRole("button", { name: "Apply to all" });
    expect((apply as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(apply);
    await waitFor(() => expect(bulkEdit).toHaveBeenCalled());
    expect((bulkEdit.mock.calls[0] as unknown[])[0]).toMatchObject({
      changes: { dns_zone_id: "za" },
    });
  });

  it("sends no zone when the fresh answer leaves none to pick", async () => {
    const bulkEdit = common();
    let release: (v: unknown) => void = () => {};
    answer(
      "ipamApi",
      "getEffectiveSubnetDns",
      () => new Promise((r) => (release = r)),
    );
    mount(cachedA);
    fireEvent.click(await screen.findByLabelText("DNS Zone"));
    fireEvent.click(screen.getByLabelText("Description"));
    release({
      dns_group_ids: [],
      dns_zone_id: null,
      dns_additional_zone_ids: [],
    });
    await waitFor(() => expect(screen.queryByLabelText("DNS Zone")).toBeNull());
    const apply = screen.getByRole("button", { name: "Apply to all" });
    await waitFor(() =>
      expect((apply as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(apply);
    await waitFor(() => expect(bulkEdit).toHaveBeenCalled());
    const changes = (
      (bulkEdit.mock.calls[0] as unknown[])[0] as {
        changes: Record<string, unknown>;
      }
    ).changes;
    expect(changes).not.toHaveProperty("dns_zone_id");
  });
});

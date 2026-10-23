/**
 * @vitest-environment jsdom
 *
 * Edit IP Block: a top-level block's DNS tab shows the DNS its space gives it (#2477).
 *
 * Each test opens the real dialog and leaves every pre-filled value alone,
 * the way a person accepts a form, then holds what the dialog SHOWS against
 * what it SENDS. Every API call a dialog makes stays pending unless a test
 * answers it, so nothing here depends on data it was not given.
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
import type { IPBlock } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
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

const { EditBlockModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

/** A spy that resolves with ``value`` and records what it was sent. */

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const block = {
  id: "b-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.98.0.0/16",
  name: "top",
  dns_inherit_settings: true,
  dns_group_ids: [],
  dns_zone_id: null,
  dns_additional_zone_ids: [],
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 65536,
} as unknown as IPBlock;

function openDnsTab(b: IPBlock) {
  answer("dnsApi", "listGroups", () =>
    Promise.resolve([{ id: "grp-1", name: "corp-dns" }]),
  );
  answer("dnsApi", "listZones", () => Promise.resolve([]));
  answer("ipamApi", "getEffectiveSpaceDns", () =>
    Promise.resolve({
      dns_group_ids: ["grp-1"],
      dns_zone_id: null,
      dns_additional_zone_ids: [],
      inherited_from_block_id: null,
    }),
  );
  answer("ipamApi", "getEffectiveBlockDns", () =>
    Promise.resolve({
      dns_group_ids: ["grp-1"],
      dns_zone_id: null,
      dns_additional_zone_ids: [],
      inherited_from_block_id: "b-0",
    }),
  );
  open(<EditBlockModal block={b} onClose={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "DNS" }));
}

describe("Edit IP Block's DNS tab (#2477)", () => {
  it("a top-level block shows the DNS server group its space gives it", async () => {
    openDnsTab(block);
    await waitFor(() => {
      const select = screen.getByText("DNS Server Group")
        .nextElementSibling as HTMLSelectElement;
      expect(select.value).toBe("grp-1");
    });
    expect(
      screen.queryByText("No DNS settings configured in parent chain."),
    ).toBeNull();
    expect(screen.getByText(/Inheriting from parent: 1 group/)).toBeTruthy();
  });

  it("a nested block still reads its parent chain", async () => {
    openDnsTab({ ...block, parent_block_id: "b-0" } as IPBlock);
    await waitFor(() => {
      const select = screen.getByText("DNS Server Group")
        .nextElementSibling as HTMLSelectElement;
      expect(select.value).toBe("grp-1");
    });
  });
});

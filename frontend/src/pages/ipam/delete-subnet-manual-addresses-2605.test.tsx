/**
 * @vitest-environment jsdom
 *
 * Delete Subnet's first step does not call manual addresses "unaffected" (#2605).
 *
 * The delete moves the subnet to Trash with its addresses, and the DNS records
 * published for them leave the zone with it; step 2 already said so. Step 1 said
 * the opposite, so the two steps of one dialog contradicted each other.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Subnet } from "@/lib/api";

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
          { get: (_t, m) => (typeof m === "symbol" ? undefined : pending) },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { EditSubnetModal } = await import("./IPAMPage");

afterEach(cleanup);

const words = (el: Element) =>
  (el.textContent ?? "").replace(/\s+/g, " ").trim();
const topDialog = () => screen.getAllByRole("dialog").at(-1)!;

const subnet = {
  id: "sn-1",
  space_id: "sp-1",
  block_id: "b-1",
  network: "10.73.5.0/24",
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 254,
} as Subnet;

describe("Delete subnet, step 1", () => {
  it("says manual addresses go to Trash, not that they are unaffected", () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <EditSubnetModal
            subnet={subnet}
            onClose={() => {}}
            onDeleted={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Danger zone" }));
    fireEvent.click(
      screen.getByRole("button", { name: /^Delete this subnet/ }),
    );
    const step1 = words(topDialog());
    expect(step1).not.toMatch(/unaffected/i);
    expect(step1).toMatch(
      /Manually-allocated addresses go to Trash with the subnet/,
    );
    expect(step1).toMatch(/stop resolving until a superadmin restores it/);
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    expect(words(topDialog())).toMatch(/stop resolving while it is in Trash/);
  });
});

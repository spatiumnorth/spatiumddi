/**
 * @vitest-environment jsdom
 *
 * IPAM's Edit Block dialog: every visible label names its control (#3340).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
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

const stored = { ...block, name: "core", description: "backbone" } as IPBlock;

describe("Edit Block labels (#3340)", () => {
  it("Name and Description are reachable by their labels", async () => {
    answer("ipamApi", "getBlock", () => Promise.resolve(stored));
    open(<EditBlockModal block={stored} onClose={() => {}} />);
    const name = (await screen.findByLabelText("Name")) as HTMLInputElement;
    expect(name.value).toBe("core");
    expect(
      (screen.getByLabelText("Description") as HTMLInputElement).value,
    ).toBe("backbone");
  });

  it("no visible label in the dialog is left naming nothing", async () => {
    answer("ipamApi", "getBlock", () => Promise.resolve(stored));
    open(<EditBlockModal block={stored} onClose={() => {}} />);
    await screen.findByLabelText("Name");
    const orphans = Array.from(document.querySelectorAll("label"))
      .filter((l) => !l.control && !l.querySelector("input,select,textarea"))
      .map((l) => l.textContent);
    expect(orphans).toEqual([]);
  });
});

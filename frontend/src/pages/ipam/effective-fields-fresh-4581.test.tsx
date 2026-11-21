/**
 * @vitest-environment jsdom
 *
 * Edit Subnet / Edit IP Block re-read the inherited (effective) custom fields
 * on open instead of serving the app's 30 s cache, so a parent block's edit
 * shows at once (#4581).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { IPBlock, Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

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

const { EditSubnetModal, EditBlockModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

// The app's own default (queryClient.ts).
const client = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 30_000 } },
  });

function mount(c: QueryClient, ui: ReactNode) {
  const r = render(
    <QueryClientProvider client={c}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  return () => r.unmount();
}

const subnet = {
  id: "s-1",
  space_id: "sp-1",
  block_id: "b-1",
  network: "10.98.1.0/24",
  name: "net",
  tags: {},
  custom_fields: {},
} as unknown as Subnet;
const block = {
  id: "b-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.98.0.0/16",
  name: "top",
  tags: {},
  custom_fields: {},
} as unknown as IPBlock;

describe("inherited fields are re-read on open (#4581)", () => {
  it("Edit Subnet reads effective-fields again when reopened", async () => {
    const read = vi.fn(() =>
      Promise.resolve({
        tags: {},
        custom_fields: {},
        custom_field_sources: {},
      }),
    );
    answer("ipamApi", "getSubnet", () => Promise.resolve(subnet));
    answer("ipamApi", "effectiveFields", read);
    const c = client();
    const ui = <EditSubnetModal subnet={subnet} onClose={() => {}} />;
    const close = mount(c, ui);
    await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
    close();
    mount(c, ui);
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  });

  it("Edit Block reads effective-fields again when reopened", async () => {
    const read = vi.fn(() =>
      Promise.resolve({
        tags: {},
        custom_fields: {},
        custom_field_sources: {},
      }),
    );
    answer("ipamApi", "getBlock", () => Promise.resolve(block));
    answer("ipamApi", "effectiveBlockFields", read);
    const c = client();
    const ui = <EditBlockModal block={block} onClose={() => {}} />;
    const close = mount(c, ui);
    await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
    close();
    mount(c, ui);
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  });
});

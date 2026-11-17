/**
 * @vitest-environment jsdom
 *
 * #3466: the VRFs page for a user whose role reads and writes VRFs and
 * nothing else. The ASN column asked GET /asns (read on `manage_asns`) for
 * each VRF linked to an ASN and, refused, showed an ellipsis titled with the
 * ASN's raw id. The row's customer chip and Edit VRF's Customer picker asked
 * GET /customers (read on `customer`) and, refused, the picker showed "None"
 * over the VRF's linked customer. Each refusal is a 403 and a denied audit
 * row, every time. Neither list is asked now without its grant, and the page
 * says the link is there but not shown.
 *
 * Every API call stays pending unless a test answers it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

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

const { VRFsPage, VRFEditorModal } = await import("./VRFsPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

const STAMP = "2026-11-05T00:00:00Z";
const VRF = {
  id: "vrf-1",
  name: "CUST-A",
  description: "old",
  asn_id: "asn-1",
  route_distinguisher: "65010:1",
  import_targets: [],
  export_targets: [],
  tags: {},
  custom_fields: {},
  customer_id: "cust-1",
  created_at: STAMP,
  modified_at: STAMP,
  space_count: 0,
  block_count: 0,
};

async function showPage() {
  answer("vrfsApi", "list", () => Promise.resolve([VRF]));
  answer("vrfsApi", "get", () => Promise.resolve(VRF));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <VRFsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const row = (await screen.findByText("CUST-A")).closest("tr")!;
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
  return row;
}

describe("VRFs page with unread permissions (#3546)", () => {
  it("a failed permissions read: the ASN cell and Customer select say so, not the role, and Save keeps both links", async () => {
    answer("authApi", "myPermissions", () =>
      Promise.reject(new Error("Network Error")),
    );
    const update = vi.fn((..._a: unknown[]) => Promise.resolve(VRF));
    answer("vrfsApi", "update", update);
    const row = await showPage();
    const cell = within(row).getByText("linked, checking permissions");
    expect(cell.getAttribute("title")).toContain("could not be read");
    expect(row.textContent).not.toMatch(/not shown|role/i);
  });

  it("a failed permissions read: the editor's Customer select says so and Save keeps the customer", async () => {
    answer("authApi", "myPermissions", () =>
      Promise.reject(new Error("Network Error")),
    );
    const update = vi.fn((..._a: unknown[]) => Promise.resolve(VRF));
    answer("vrfsApi", "update", update);
    answer("vrfsApi", "get", () => Promise.resolve(VRF));
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <VRFEditorModal existing={VRF as never} onClose={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const sel = (await waitFor(() => {
      const hit = screen
        .getAllByRole("combobox")
        .filter((el) => (el as HTMLSelectElement).title.includes("could not"));
      if (hit.length < 2) throw new Error("not yet");
      return hit[1];
    })) as HTMLSelectElement;
    expect(sel.disabled).toBe(true);
    expect(sel.title).not.toMatch(/role/i);
    expect(sel.selectedOptions[0].textContent).not.toMatch(/role/i);
    fireEvent.change(screen.getByDisplayValue("old"), {
      target: { value: "new" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    // The links are not in the body, so they are not cleared.
    expect((update.mock.calls[0] as unknown as [string, object])[1]).toEqual({
      description: "new",
    });
  });

  it("with permissions read and no grant, the role wording stays", async () => {
    answer("authApi", "myPermissions", () =>
      Promise.resolve({
        is_superadmin: false,
        grants: [{ action: "read", resource_type: "vrf", resource_id: null }],
      }),
    );
    const row = await showPage();
    expect(within(row).getByText("linked, not shown")).toBeTruthy();
  });
});

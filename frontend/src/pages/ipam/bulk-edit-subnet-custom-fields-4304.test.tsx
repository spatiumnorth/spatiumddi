/**
 * @vitest-environment jsdom
 *
 * The subnet Bulk edit dialog carries the address dialog's custom-field
 * section: tick a field to write it, a ticked field left empty clears it
 * (sent as null, which the bulk API reads as "remove the key"), unticked
 * fields are not sent (#4304).
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
import type { CustomField } from "@/lib/api";

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

const { BulkEditSubnetsModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const def = (name: string, label: string, over: Partial<CustomField> = {}) =>
  ({
    id: name,
    resource_type: "subnet",
    name,
    label,
    field_type: "text",
    options: null,
    is_required: false,
    is_searchable: false,
    default_value: null,
    display_order: 0,
    description: "",
    ...over,
  }) as CustomField;

function mount() {
  answers.customFieldsApi = {
    list: () =>
      Promise.resolve([
        def("owner", "Owner"),
        def("site", "Site", { field_type: "select", options: ["a", "b"] }),
        def("other", "Other"),
      ]),
  };
  const bulk = vi.fn(() =>
    Promise.resolve({ batch_id: "b", updated_count: 2, not_found: [] }),
  );
  answers.ipamApi = { bulkEditSubnets: bulk };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <BulkEditSubnetsModal
          subnetIds={["s1", "s2"]}
          onClose={() => {}}
          onDone={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return bulk;
}

async function openSection() {
  fireEvent.click(await screen.findByLabelText("Custom fields (merge)"));
}

describe("Subnet bulk edit custom fields (#4304)", () => {
  it("lists the subnet custom fields", async () => {
    mount();
    await openSection();
    expect(await screen.findByLabelText("Owner")).toBeTruthy();
    expect(screen.getByLabelText("Site")).toBeTruthy();
  });

  it("sends a ticked field with its value and omits unticked ones", async () => {
    const bulk = mount();
    await openSection();
    fireEvent.click(await screen.findByLabelText("Owner"));
    fireEvent.change(screen.getByPlaceholderText("(empty clears field)"), {
      target: { value: "neteng" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(bulk).toHaveBeenCalled());
    const [ids, changes] = bulk.mock.calls[0] as unknown as [string[], object];
    expect(ids).toEqual(["s1", "s2"]);
    expect(changes).toEqual({ custom_fields: { owner: "neteng" } });
  });

  it("sends null for a ticked field left empty (clear)", async () => {
    const bulk = mount();
    await openSection();
    fireEvent.click(await screen.findByLabelText("Site"));
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(bulk).toHaveBeenCalled());
    expect((bulk.mock.calls[0] as unknown[])[1]).toEqual({
      custom_fields: { site: null },
    });
  });

  it("sends no custom_fields when nothing is ticked", async () => {
    const bulk = mount();
    fireEvent.change(await screen.findAllByRole("textbox").then((e) => e[0]), {
      target: { value: "renamed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(bulk).toHaveBeenCalled());
    expect((bulk.mock.calls[0] as unknown[])[1]).toEqual({ name: "renamed" });
  });
});

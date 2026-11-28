/**
 * @vitest-environment jsdom
 *
 * A custom-field select whose stored value was removed from the field's
 * options still shows that value (#4840).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { CustomField, IPBlock } from "@/lib/api";

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

const { EditBlockModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function field(name: string, required: boolean): CustomField {
  return {
    id: `cf-${name}`,
    resource_type: "ip_block",
    name,
    label: name,
    field_type: "select",
    options: ["gold", "silver"],
    is_required: required,
    is_searchable: false,
    default_value: null,
    display_order: 0,
    description: "",
  };
}

describe("select custom field with a removed option (#4840)", () => {
  it("Edit IP Block shows the stored value, optional and Required", async () => {
    answers.customFieldsApi = {
      list: () =>
        Promise.resolve([field("tier", false), field("tier_req", true)]),
    };
    answers.ipamApi = {
      effectiveBlockFields: () =>
        Promise.resolve({ custom_fields: {}, custom_field_sources: {} }),
    };
    const block = {
      id: "b-1",
      space_id: "sp-1",
      parent_block_id: null,
      network: "10.98.0.0/16",
      name: "top",
      custom_fields: { tier: "copper", tier_req: "copper" },
      tags: {},
      utilization_percent: 0,
      total_ips: 65536,
    } as unknown as IPBlock;
    answers.ipamApi.getBlock = () => Promise.resolve(block);
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <EditBlockModal block={block} onClose={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    for (const label of ["tier", "tier_req *"]) {
      const sel = (await screen.findByText(label, { selector: "label" }))
        .nextElementSibling as HTMLSelectElement;
      expect(sel.value).toBe("copper");
    }
  });
});

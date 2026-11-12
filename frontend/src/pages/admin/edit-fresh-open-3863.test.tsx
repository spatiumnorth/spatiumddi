/**
 * @vitest-environment jsdom
 *
 * Edit template and Edit custom field read the object when they open and send
 * only what the operator changed (#3863), the #3365 / #3739 pattern. The list
 * holds a stale copy while the API holds what another client stored since.
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
import type { CustomField, IPAMTemplate } from "@/lib/api";

const staleTpl = {
  id: "t1",
  name: "tpl",
  description: "old",
  applies_to: "subnet",
  tags: {},
  custom_fields: {},
  dns_group_id: null,
  dns_zone_id: null,
  dns_additional_zone_ids: null,
  dhcp_group_id: null,
  ddns_enabled: false,
  ddns_hostname_policy: "client_or_generated",
  ddns_domain_override: null,
  ddns_ttl: null,
  child_layout: null,
  applied_count: 0,
  created_at: "",
  modified_at: "",
} as IPAMTemplate;
const freshTpl = {
  ...staleTpl,
  tags: { owner: "theirs" },
  dns_group_id: "g1",
} as IPAMTemplate;

const staleField: CustomField = {
  id: "f1",
  resource_type: "subnet",
  name: "cf",
  label: "Old",
  field_type: "select",
  options: ["xa", "xb"],
  is_required: false,
  is_searchable: false,
  default_value: null,
  display_order: 0,
  description: "",
};
const freshField: CustomField = {
  ...staleField,
  options: ["xa", "xb", "xc"],
  is_searchable: true,
};

const updateTemplate = vi.fn((_id: string, _b: unknown) =>
  Promise.resolve(freshTpl),
);
const updateField = vi.fn((_id: string, _b: unknown) =>
  Promise.resolve(freshField),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    ipamApi: {
      listTemplates: () => Promise.resolve([staleTpl]),
      getTemplate: () => Promise.resolve(freshTpl),
      updateTemplate: (id: string, b: unknown) => updateTemplate(id, b),
    },
    dnsApi: { listGroups: () => Promise.resolve([]) },
    dhcpApi: { listGroups: () => Promise.resolve([]) },
    customFieldsApi: {
      list: () => Promise.resolve([staleField]),
      get: () => Promise.resolve(freshField),
      update: (id: string, b: unknown) => updateField(id, b),
    },
  };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { IPAMTemplatesPage } = await import("./IPAMTemplatesPage");
const { CustomFieldsPage } = await import("./CustomFieldsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function open(ui: React.ReactNode) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("#3863", () => {
  it("Edit template sends only the Description, not the tags or DNS group another client set", async () => {
    open(<IPAMTemplatesPage />);
    fireEvent.click(await screen.findByLabelText("Edit template tpl"));
    const desc = await screen.findByDisplayValue("old");
    fireEvent.change(desc, { target: { value: "new" } });
    fireEvent.click(screen.getByRole("button", { name: /^save/i }));
    await waitFor(() => expect(updateTemplate).toHaveBeenCalled());
    expect(updateTemplate).toHaveBeenCalledWith("t1", { description: "new" });
  });

  it("Edit custom field sends only the Label, not the options or Searchable another client set", async () => {
    open(<CustomFieldsPage />);
    fireEvent.click(await screen.findByTitle("Edit"));
    const label = await screen.findByDisplayValue("Old");
    // the form shows the fresh options, not the list's copy
    expect(await screen.findByDisplayValue("xa, xb, xc")).toBeTruthy();
    fireEvent.change(label, { target: { value: "New" } });
    fireEvent.click(screen.getByRole("button", { name: /^save/i }));
    await waitFor(() => expect(updateField).toHaveBeenCalled());
    expect(updateField).toHaveBeenCalledWith("f1", { label: "New" });
  });
});

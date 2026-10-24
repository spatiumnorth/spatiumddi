/**
 * @vitest-environment jsdom
 *
 * Custom Fields offers its writes to exactly the callers the server lets
 * make them (#2697). The router takes `require_resource_permission(
 * "custom_field")` (write for create / update, delete for delete), so the
 * built-in IPAM Editor gets New Field, Edit and Delete; a read-only Viewer
 * gets none of them.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { MyPermissions } from "@/lib/api";

const myPermissions = vi.fn<() => Promise<MyPermissions>>();

vi.mock("@/lib/api", () => ({
  authApi: { myPermissions: () => myPermissions() },
  customFieldsApi: {
    list: () =>
      Promise.resolve([
        {
          id: "f1",
          resource_type: "subnet",
          name: "cf_probe",
          label: "cf probe",
          field_type: "text",
          options: null,
          is_required: false,
          is_searchable: false,
          default_value: null,
          display_order: 0,
          description: "",
        },
      ]),
  },
}));

const { CustomFieldsPage } = await import("./CustomFieldsPage");

function grants(...g: [string, string][]): MyPermissions {
  return {
    is_superadmin: false,
    grants: g.map(([action, resource_type]) => ({
      action,
      resource_type,
      resource_id: null,
    })),
  } as MyPermissions;
}

async function show(perms: MyPermissions) {
  myPermissions.mockResolvedValue(perms);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <CustomFieldsPage />
    </QueryClientProvider>,
  );
  await screen.findByText("cf_probe");
  await waitFor(() => expect(myPermissions).toHaveBeenCalled());
  await new Promise((r) => setTimeout(r, 20));
}

afterEach(() => cleanup());

describe("Custom Fields write gates (#2697)", () => {
  it("offers New Field, Edit and Delete to the IPAM Editor", async () => {
    await show(grants(["admin", "custom_field"], ["admin", "subnet"]));
    expect(
      await screen.findByRole("button", { name: /New Field/ }),
    ).toBeTruthy();
    expect(screen.getByTitle("Edit")).toBeTruthy();
    expect(screen.getByTitle("Delete")).toBeTruthy();
    expect(screen.getByText("Actions")).toBeTruthy();
  });

  it("offers none of them to a Viewer", async () => {
    await show(grants(["read", "*"]));
    expect(screen.queryByRole("button", { name: /New Field/ })).toBeNull();
    expect(screen.queryByTitle("Edit")).toBeNull();
    expect(screen.queryByTitle("Delete")).toBeNull();
    expect(screen.queryByText("Actions")).toBeNull();
  });

  it("offers Edit without Delete to a write-only grant", async () => {
    await show(grants(["write", "custom_field"], ["read", "custom_field"]));
    expect(screen.getByTitle("Edit")).toBeTruthy();
    expect(screen.queryByTitle("Delete")).toBeNull();
  });
});

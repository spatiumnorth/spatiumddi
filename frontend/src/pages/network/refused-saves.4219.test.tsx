/**
 * @vitest-environment jsdom
 *
 * A refused save in the E911 location dialog and the Requests page's New
 * request dialog is announced inside the dialog (#4219): a plain red line is
 * not read by a screen reader, so Save said nothing.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const refuse = (status: number, detail: string) =>
  Object.assign(new Error(String(status)), {
    response: { status, data: { detail } },
  });

const api = { createErl: vi.fn(), submit: vi.fn() };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const empty = { items: [], total: 0, limit: 50, offset: 0 };
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "u9" }) },
    e911Api: {
      ...actual.e911Api,
      listErls: async () => empty,
      listBindings: async () => empty,
      createErl: (...a: unknown[]) => api.createErl(...a),
    },
    requestsApi: {
      ...actual.requestsApi,
      listPage: async () => ({ items: [], total: 0 }),
      catalog: async () => [
        {
          kind: "subnet",
          label: "New subnet",
          operation: "allocate_subnet",
          description: "Carve a subnet.",
          category: "ipam",
          args_schema: { required: [], properties: {} },
        },
      ],
      submit: (...a: unknown[]) => api.submit(...a),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
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

const { E911Page } = await import("@/pages/network/E911Page");
const { default: RequestsPage } = await import("@/pages/RequestsPage");

function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  api.createErl.mockReset();
  api.submit.mockReset();
});

describe("a refused save is announced in its dialog (#4219)", () => {
  it("New Emergency Response Location", async () => {
    api.createErl.mockRejectedValue(
      refuse(409, "An ERL named 'A' already exists"),
    );
    show(<E911Page />);
    fireEvent.click(
      await screen.findByRole("button", { name: /Add location/ }),
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getAllByRole("textbox")[0], {
      target: { value: "A" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(within(dialog).getByRole("alert").textContent).toContain(
        "already exists",
      ),
    );
  });

  it("New request", async () => {
    api.submit.mockRejectedValue(refuse(409, "That address is taken"));
    show(<RequestsPage />);
    fireEvent.click(await screen.findByRole("button", { name: /New request/ }));
    const select = await screen.findByDisplayValue("Select…");
    await screen.findByRole("option", { name: "New subnet" });
    fireEvent.change(select, { target: { value: "subnet" } });
    const dialog = screen.getByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Submit request" }),
    );
    await waitFor(() =>
      expect(within(dialog).getByRole("alert").textContent).toContain("taken"),
    );
  });
});

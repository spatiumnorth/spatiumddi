/**
 * @vitest-environment jsdom
 *
 * The Custom Fields form offers `multi_select` and `date` (#4288), and a
 * multi_select gets the options editor a select has.
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

const create = vi.fn(() => Promise.resolve({}));

vi.mock("@/lib/api", () => ({
  authApi: {
    myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
  },
  customFieldsApi: { list: () => Promise.resolve([]), create },
  formatApiError: (e: unknown) => String(e),
}));

const { CustomFieldsPage } = await import("./CustomFieldsPage");

afterEach(() => cleanup());

describe("Custom Fields form, multi_select and date (#4288)", () => {
  it("offers both types, shows options for multi_select, and sends them", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <CustomFieldsPage />
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByRole("button", { name: /New Field/ }));
    const type = (await screen.findByDisplayValue("Text")) as HTMLSelectElement;
    const values = Array.from(type.options).map((o) => o.value);
    expect(values).toContain("multi_select");
    expect(values).toContain("date");

    fireEvent.change(type, { target: { value: "date" } });
    expect(screen.queryByPlaceholderText(/Option A/)).toBeNull();

    fireEvent.change(type, { target: { value: "multi_select" } });
    fireEvent.change(screen.getByPlaceholderText(/Option A/), {
      target: { value: "a, b" },
    });
    fireEvent.change(screen.getByPlaceholderText("e.g. location_code"), {
      target: { value: "sites" },
    });
    fireEvent.change(screen.getByPlaceholderText("e.g. Location Code"), {
      target: { value: "Sites" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(create.mock.calls[0]).toBeTruthy();
    const sent = (create.mock.calls[0] as unknown[])[0] as Record<
      string,
      unknown
    >;
    expect(sent.field_type).toBe("multi_select");
    expect(sent.options).toEqual(["a", "b"]);
  });
});

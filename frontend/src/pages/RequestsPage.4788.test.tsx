/**
 * @vitest-environment jsdom
 *
 * A failed read is not an empty answer (#4788): the New request resource
 * picker, its request type list and the admin Change Requests queue each say
 * the read failed instead of "No matches you can read", a bare "Select…" or
 * "Nothing waiting for approval.".
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const fail = (status: number, detail: unknown) =>
  Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    response: { status, data: { detail } },
  });

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "u9" }) },
    requestsApi: {
      ...actual.requestsApi,
      listPage: async () => ({ items: [], total: 0 }),
      catalog: async () => Promise.reject(fail(503, "Service unavailable")),
      resourceOptions: async () =>
        Promise.reject(
          fail(422, [
            {
              type: "string_too_long",
              msg: "String should have at most 200 characters",
            },
          ]),
        ),
    },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      listPage: async () => Promise.reject(fail(503, "Service unavailable")),
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: true }),
}));

import RequestsPage, { ResourcePicker } from "./RequestsPage";
import { ChangeRequestsPage } from "./admin/ChangeRequestsPage";

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("failed reads are not empty answers (#4788)", () => {
  it("the picker says its read failed and caps the search at 200", async () => {
    wrap(<ResourcePicker resource="subnet" value="" onChange={() => {}} />);
    const input = screen.getByPlaceholderText("Type to search…");
    expect(input.getAttribute("maxlength")).toBe("200");
    fireEvent.focus(input);
    expect(await screen.findByText(/Couldn't load the options/)).toBeTruthy();
    expect(screen.queryByText("No matches you can read")).toBeNull();
  });

  it("a failed request type read is said in the New request dialog", async () => {
    wrap(<RequestsPage />);
    fireEvent.click(await screen.findByText("New request"));
    expect(
      await screen.findByText(/Couldn't load the request types/),
    ).toBeTruthy();
  });

  it("the admin queue says its read failed", async () => {
    wrap(<ChangeRequestsPage />);
    expect(
      await screen.findByText(/Couldn't load change requests/),
    ).toBeTruthy();
    expect(screen.queryByText("Nothing waiting for approval.")).toBeNull();
  });
});

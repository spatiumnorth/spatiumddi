/**
 * @vitest-environment jsdom
 *
 * A refused community save shows the server's reason instead of crashing
 * the dialog (#2624): a 422's detail is a list of error objects, and
 * rendering it as a React child threw (minified React error #31).
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

const REFUSAL = Object.assign(
  new Error("Request failed with status code 422"),
  {
    response: {
      status: 422,
      data: {
        detail: [
          {
            type: "value_error",
            loc: ["body", "value"],
            msg: "Value error, large community must be ASN:N:M (e.g. 65000:100:200)",
            input: "4221370486:100:200",
          },
        ],
      },
    },
  },
);

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
                : name === "asnsApi" && method === "listCommunities"
                  ? async () => []
                  : name === "asnsApi" && method === "listStandardCommunities"
                    ? async () => []
                    : name === "asnsApi" && method === "createCommunity"
                      ? async () => {
                          throw REFUSAL;
                        }
                      : name === "authApi" && method === "myPermissions"
                        ? async () => ({ is_superadmin: true, grants: [] })
                        : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { CommunitiesTab } = await import("./CommunitiesTab");

afterEach(cleanup);

describe("CommunitiesTab: a refused Add", () => {
  it("shows the server's reason and keeps the dialog open", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <CommunitiesTab asnId="a1" />
      </QueryClientProvider>,
    );
    const add = (await screen.findByRole("button", {
      name: /Add Community/,
    })) as HTMLButtonElement;
    await waitFor(() => expect(add.disabled).toBe(false));
    fireEvent.click(add);
    fireEvent.click(await screen.findByLabelText(/Large/));
    fireEvent.change(await screen.findByPlaceholderText("65000:100:200"), {
      target: { value: "4221370486:100:200" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(
      await screen.findByText(/large community must be ASN:N:M/),
    ).toBeTruthy();
    expect(screen.getByText("Add BGP community")).toBeTruthy();
  });
});

/**
 * @vitest-environment jsdom
 *
 * A refused DNSSEC policy save and a refused pool save show the reason (#2465).
 *
 * The 422's `detail` is pydantic's list of `{type, loc, msg, input, ctx}`
 * objects. Both dialogs put it into their error state as if it were a string
 * and rendered it as a React child, which threw error #31 and replaced the
 * whole page with the error boundary. They now say why, as text, and stay open.
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
import type { DNSServerGroup, DNSZone } from "@/lib/api";

function refusal(msg: string, loc: string[]) {
  return Object.assign(new Error("Request failed with status code 422"), {
    response: {
      status: 422,
      data: {
        detail: [
          {
            type: "value_error",
            loc: ["body", ...loc],
            msg,
            input: "x",
            ctx: {},
          },
        ],
      },
    },
  });
}

const createPool = vi.fn((..._a: unknown[]) =>
  Promise.reject(
    refusal("Value error, invalid IP address: web01", ["members", "0"]),
  ),
);
const createDnssecPolicy = vi.fn((..._a: unknown[]) =>
  Promise.reject(
    refusal("Value error, name must be 1-64 chars of [A-Za-z0-9_-]", ["name"]),
  ),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      createPool: (...a: unknown[]) => createPool(...a),
      createDnssecPolicy: (...a: unknown[]) => createDnssecPolicy(...a),
      listDnssecPolicies: () => Promise.resolve([]),
    },
    sitesApi: { ...actual.sitesApi, list: () => new Promise<never>(() => {}) },
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

const { PoolModal } = await import("./PoolsView");
const { DNSSECPoliciesPage } = await import("./DNSSECPoliciesPage");

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  createPool.mockClear();
  createDnssecPolicy.mockClear();
});

describe("a refused save shows the server's reason as text (#2465)", () => {
  it("New DNSSEC policy stays open and names the field", async () => {
    wrap(<DNSSECPoliciesPage />);
    fireEvent.click(await screen.findByRole("button", { name: /New policy/ }));
    const name = screen
      .getByText("Name", { selector: "label" })
      .querySelector("input") as HTMLInputElement;
    fireEvent.change(name, { target: { value: "my policy" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(createDnssecPolicy).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText(/name: Value error, name must be 1-64 chars/),
    ).toBeTruthy();
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(document.body.textContent).not.toContain("[object Object]");
  });

  it("New DNS pool stays open and says which member was refused", async () => {
    wrap(
      <PoolModal
        group={{ id: "g1" } as DNSServerGroup}
        zone={{ id: "z1" } as DNSZone}
        onClose={() => {}}
      />,
    );
    const name = screen.getByText("Name", { selector: "label" })
      .nextElementSibling as HTMLInputElement;
    fireEvent.change(name, { target: { value: "web" } });
    fireEvent.submit(name.form!);

    await waitFor(() => expect(createPool).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText(
        /members\.0: Value error, invalid IP address: web01/,
      ),
    ).toBeTruthy();
    expect(screen.getByRole("dialog")).toBeTruthy();
  });
});

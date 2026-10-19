/**
 * @vitest-environment jsdom
 *
 * The pool TTL field reads what was typed (#2086). `parseInt` read "1h" as 1
 * and turned a cleared field into 30 without saying so; the field now refuses
 * both, within the API's own 1..86400.
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
import type { DNSServerGroup, DNSZone } from "@/lib/api";

const createPool = vi.fn((_g: string, _z: string, data: unknown) =>
  Promise.resolve({ id: "pool-1", ...(data as object) }),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      createPool: (g: string, z: string, data: unknown) =>
        createPool(g, z, data),
    },
    sitesApi: {
      ...actual.sitesApi,
      list: () => new Promise<never>(() => {}),
    },
  };
});

const { PoolModal } = await import("./PoolsView");

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <PoolModal
        group={{ id: "g1" } as DNSServerGroup}
        zone={{ id: "z1" } as DNSZone}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

function ttlInput(): HTMLInputElement {
  return screen.getByText("TTL (seconds)", { selector: "label" })
    .nextElementSibling as HTMLInputElement;
}

function submit() {
  fireEvent.change(
    screen.getByText("Name", { selector: "label" })
      .nextElementSibling as HTMLInputElement,
    { target: { value: "web" } },
  );
  fireEvent.submit(ttlInput().form!);
}

afterEach(() => {
  cleanup();
  createPool.mockClear();
});

describe("pool TTL (#2086)", () => {
  it("opens on the default 30", () => {
    open();
    expect(ttlInput().value).toBe("30");
  });

  it.each(["1h", "30s", "1.5", "-1", "0", "86401", ""])(
    "refuses %j with a reason and sends nothing",
    async (text) => {
      open();
      fireEvent.change(ttlInput(), { target: { value: text } });
      submit();
      await waitFor(() =>
        expect(screen.getByText(/^TTL (must|is required)/)).toBeTruthy(),
      );
      expect(createPool).not.toHaveBeenCalled();
    },
  );

  it("says a cleared field is required rather than saving 30", async () => {
    open();
    fireEvent.change(ttlInput(), { target: { value: "" } });
    submit();
    await waitFor(() => screen.getByText("TTL is required."));
  });

  it("reads 1e3 as 1000", async () => {
    open();
    fireEvent.change(ttlInput(), { target: { value: "1e3" } });
    submit();
    await waitFor(() => expect(createPool).toHaveBeenCalledTimes(1));
    expect((createPool.mock.calls[0][2] as { ttl: number }).ttl).toBe(1000);
  });
});

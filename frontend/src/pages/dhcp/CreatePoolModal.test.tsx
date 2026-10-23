/**
 * @vitest-environment jsdom
 *
 * #2481 — Edit Pool shows a stored class restriction the group's class list
 * does not hold (Kea's KNOWN, generated classes) as itself, and an untouched
 * Save keeps it.
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
import type { DHCPPool, DHCPScope } from "@/lib/api";

const updatePool = vi.fn();
vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listClientClasses: () => Promise.resolve([{ id: "c1", name: "voip" }]),
    updatePool: (...a: unknown[]) => updatePool(...a),
    createPool: vi.fn(),
  },
}));

const { CreatePoolModal } = await import("./CreatePoolModal");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Edit Pool class restriction (#2481)", () => {
  it("shows KNOWN as itself and keeps it on an untouched Save", async () => {
    updatePool.mockResolvedValue({});
    const pool = {
      id: "p1",
      name: "p",
      start_ip: "10.0.0.10",
      end_ip: "10.0.0.20",
      pool_type: "dynamic",
      class_restriction: "KNOWN",
    } as unknown as DHCPPool;
    const scope = {
      id: "s1",
      group_id: "g1",
      address_family: "ipv4",
    } as DHCPScope;
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CreatePoolModal pool={pool} scope={scope} onClose={() => {}} />
      </QueryClientProvider>,
    );
    const sel = screen.getByText("Restrict to Client Class", {
      selector: "label",
    }).nextElementSibling as HTMLSelectElement;
    await waitFor(() =>
      expect(sel.selectedOptions[0].textContent).toMatch(/KNOWN/),
    );
    expect(sel.value).toBe("KNOWN");
    fireEvent.submit(sel.form!);
    await waitFor(() => expect(updatePool).toHaveBeenCalled());
    expect(updatePool.mock.calls[0][2].class_restriction).toBe("KNOWN");
  });
});

/**
 * @vitest-environment jsdom
 *
 * #3854 — the HA Hook Tuning note must not call every default Kea's own while
 * the dialog pre-fills a 2 s heartbeat (Kea documents 10 s, #3779).
 */
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DHCPServerGroup } from "@/lib/api";

let stored: unknown;
vi.mock("@/lib/api", () => ({
  dhcpApi: {
    createGroup: vi.fn(),
    updateGroup: vi.fn(),
    getGroup: () => Promise.resolve(stored),
  },
}));

const { CreateServerGroupModal } = await import("./CreateServerGroupModal");
afterEach(cleanup);

it("names the 2 s heartbeat as SpatiumDDI's own, not Kea's", async () => {
  const group = {
    id: "g",
    name: "ha",
    description: "",
    mode: "hot-standby",
  } as unknown as DHCPServerGroup;
  stored = group;
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateServerGroupModal group={group} onClose={() => {}} />
    </QueryClientProvider>,
  );
  const note = (await screen.findByText("HA Hook Tuning")).nextElementSibling!;
  const text = note.textContent ?? "";
  expect(text).not.toMatch(/Defaults match Kea/);
  expect(text).toMatch(/Heartbeat Delay is SpatiumDDI/);
  expect(text).toMatch(/Kea documents 10 s/);
  const hb = screen.getByText("Heartbeat Delay (ms)", { selector: "label" })
    .nextElementSibling as HTMLInputElement;
  expect(hb.value).toBe("2000");
});

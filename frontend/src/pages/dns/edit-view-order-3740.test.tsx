/**
 * @vitest-environment jsdom
 *
 * #3740: a cleared Order was saved as 0, moving the view ahead of every view
 * ordered 1 and up. It is refused now.
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
import type { ReactNode } from "react";
import type { DNSView } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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
            get:
              (_t, method: string) =>
              (...args: unknown[]) =>
                (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { ViewModal } = await import("@/pages/dns/DNSPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const view = {
  id: "v-1",
  group_id: "g-1",
  name: "internal",
  description: "",
  order: 10,
  recursion: true,
  match_clients: ["any"],
  match_destinations: [],
} as unknown as DNSView;

const save = () =>
  fireEvent.click(screen.getByRole("button", { name: /^(Save|Create)/ }));

describe("View Order (#3740)", () => {
  it("Edit: a cleared Order is refused, nothing is sent", async () => {
    const updateView = vi.fn(() => Promise.resolve(view));
    answers.dnsApi = { listViews: () => Promise.resolve([view]), updateView };
    const onClose = vi.fn();
    open(<ViewModal groupId="g-1" view={view} onClose={onClose} />);
    const box = await screen.findByLabelText("Order");
    fireEvent.change(box, { target: { value: "" } });
    save();
    await screen.findByText(/Order is required/);
    expect(updateView).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("New: a cleared Order is refused too", async () => {
    const createView = vi.fn(() => Promise.resolve(view));
    answers.dnsApi = { createView };
    open(<ViewModal groupId="g-1" view={null} onClose={() => {}} />);
    fireEvent.change(await screen.findByLabelText("Name"), {
      target: { value: "x" },
    });
    fireEvent.change(screen.getByLabelText("Order"), { target: { value: "" } });
    save();
    await screen.findByText(/Order is required/);
    expect(createView).not.toHaveBeenCalled();
  });

  it("Edit: a typed Order is still saved", async () => {
    const updateView = vi.fn(() => Promise.resolve(view));
    answers.dnsApi = { listViews: () => Promise.resolve([view]), updateView };
    open(<ViewModal groupId="g-1" view={view} onClose={() => {}} />);
    fireEvent.change(await screen.findByLabelText("Order"), {
      target: { value: "3" },
    });
    save();
    await waitFor(() => expect(updateView).toHaveBeenCalled());
    expect(updateView).toHaveBeenCalledWith("g-1", "v-1", { order: 3 });
  });
});

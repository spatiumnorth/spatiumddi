/**
 * @vitest-environment jsdom
 *
 * #3523: the view editor sets a view's own default forwarders. An empty box
 * inherits the group's (sent as null), and an edit sends only what changed.
 *
 * Every API call stays pending unless a test answers it.
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
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { ViewModal } = await import("./DNSPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

const view: DNSView = {
  id: "v1",
  group_id: "grp-1",
  name: "guest",
  description: "",
  match_clients: ["10.9.0.0/16"],
  match_destinations: [],
  recursion: true,
  order: 0,
  allow_query: null,
  allow_query_cache: null,
  forwarders: null,
  forward_policy: null,
  forward_transport: "do53",
  forward_tls_hostname: null,
  dnssec_validation: null,
  allow_recursion: null,
  rrl_enabled: null,
  rrl_responses_per_second: null,
  rrl_window: null,
  rrl_slip: null,
  minimal_responses: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
};

function open(row: DNSView) {
  answer("dnsApi", "listViews", () => Promise.resolve([row]));
  answer("dnsApi", "forwarderPresets", () =>
    Promise.resolve({ version: "test", presets: [] }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ViewModal groupId="grp-1" view={row} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("view forwarders (#3523)", () => {
  it("says it inherits the group's when empty, and an untouched save sends nothing", async () => {
    const update = vi.fn(() => Promise.resolve(view));
    answer("dnsApi", "updateView", update);
    open(view);
    const box = (await screen.findByLabelText(
      "View forwarders",
    )) as HTMLTextAreaElement;
    expect(box.placeholder).toContain("Inherits the group's forwarders");
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(update).not.toHaveBeenCalled());
  });

  it("sends the typed forwarders and policy, and null again when cleared", async () => {
    const update = vi.fn(() => Promise.resolve(view));
    answer("dnsApi", "updateView", update);
    open(view);
    const box = await screen.findByLabelText("View forwarders");
    fireEvent.change(box, { target: { value: "1.1.1.3\n1.0.0.3@5353" } });
    fireEvent.change(screen.getByLabelText("Fallback policy"), {
      target: { value: "only" },
    });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith("grp-1", "v1", {
      forwarders: ["1.1.1.3", "1.0.0.3@5353"],
      forward_policy: "only",
    });
  });

  it("clearing a stored set sends null so the view inherits again", async () => {
    const update = vi.fn(() => Promise.resolve(view));
    answer("dnsApi", "updateView", update);
    open({ ...view, forwarders: ["9.9.9.9"], forward_policy: "only" });
    const box = await screen.findByLabelText("View forwarders");
    fireEvent.change(box, { target: { value: "" } });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith("grp-1", "v1", {
      forwarders: null,
      forward_policy: null,
    });
  });
});

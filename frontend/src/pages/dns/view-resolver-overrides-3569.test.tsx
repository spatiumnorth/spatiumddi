/**
 * @vitest-environment jsdom
 *
 * #3569: the view editor sets a view's own dnssec-validation, allow-recursion,
 * rate-limit and minimal-responses. "Inherit" is sent as null, and an edit
 * sends only what changed.
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

describe("view resolver overrides (#3569)", () => {
  it("an untouched save sends nothing", async () => {
    const update = vi.fn(() => Promise.resolve(view));
    answer("dnsApi", "updateView", update);
    open(view);
    await screen.findByLabelText("View allow-recursion");
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(update).not.toHaveBeenCalled());
  });

  it("sends the chosen overrides", async () => {
    const update = vi.fn(() => Promise.resolve(view));
    answer("dnsApi", "updateView", update);
    open(view);
    fireEvent.change(await screen.findByLabelText("DNSSEC validation"), {
      target: { value: "no" },
    });
    fireEvent.change(screen.getByLabelText("View allow-recursion"), {
      target: { value: "10.0.0.0/8\nlocalhost" },
    });
    fireEvent.change(screen.getByLabelText("Response rate limiting"), {
      target: { value: "true" },
    });
    fireEvent.change(screen.getByLabelText("Responses / second"), {
      target: { value: "5" },
    });
    fireEvent.change(screen.getByLabelText("Minimal responses"), {
      target: { value: "false" },
    });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith("grp-1", "v1", {
      dnssec_validation: "no",
      allow_recursion: ["10.0.0.0/8", "localhost"],
      rrl_enabled: true,
      rrl_responses_per_second: 5,
      minimal_responses: false,
    });
  });

  it("choosing Inherit again sends null for a stored override", async () => {
    const update = vi.fn(() => Promise.resolve(view));
    answer("dnsApi", "updateView", update);
    open({
      ...view,
      dnssec_validation: "yes",
      rrl_enabled: false,
      allow_recursion: ["any"],
      minimal_responses: true,
    });
    fireEvent.change(await screen.findByLabelText("DNSSEC validation"), {
      target: { value: "" },
    });
    fireEvent.change(screen.getByLabelText("Response rate limiting"), {
      target: { value: "" },
    });
    fireEvent.change(screen.getByLabelText("View allow-recursion"), {
      target: { value: "" },
    });
    fireEvent.change(screen.getByLabelText("Minimal responses"), {
      target: { value: "" },
    });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith("grp-1", "v1", {
      dnssec_validation: null,
      allow_recursion: null,
      rrl_enabled: null,
      minimal_responses: null,
    });
  });
});

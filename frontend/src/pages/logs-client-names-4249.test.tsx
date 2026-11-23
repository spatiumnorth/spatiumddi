/**
 * @vitest-environment jsdom
 *
 * Logs → DNS Queries client name resolution (#4249).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSQueryLogRow } from "@/lib/api";

const dnsQueries = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return {
    ...mod,
    logsApi: { ...mod.logsApi, dnsQueries, dnsQueryAnalytics: vi.fn() },
    ipamApi: {
      ...mod.ipamApi,
      listSpaces: vi.fn().mockResolvedValue([{ id: "sp-1", name: "Corp" }]),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, isLoading: false }),
}));

import { DNSQueriesTab, DNSQueryRow } from "./LogsPage";

afterEach(cleanup);
beforeEach(() => {
  sessionStorage.clear();
  dnsQueries.mockReset();
});

const row: DNSQueryLogRow = {
  id: 1,
  ts: "2026-10-20T09:12:33.123Z",
  server_id: "s",
  server_name: "ns1",
  client_ip: "10.0.0.5",
  client_port: 5000,
  qname: "foo.example.com",
  qclass: "IN",
  qtype: "A",
  flags: "+",
  view: null,
  rcode: "NOERROR",
  answer_count: 1,
  raw: "q",
  client_name: "laptop-7",
  client_name_source: "ipam",
};

describe("client name rendering (#4249)", () => {
  it("shows the name with the address beneath", () => {
    render(<DNSQueryRow row={row} />);
    expect(screen.getByText("laptop-7")).toBeTruthy();
    expect(screen.getByText("10.0.0.5")).toBeTruthy();
  });

  it("shows the address alone when unresolved", () => {
    render(<DNSQueryRow row={{ ...row, client_name: null }} />);
    expect(screen.getByText("10.0.0.5")).toBeTruthy();
    expect(screen.queryByText("laptop-7")).toBeNull();
  });

  it("names the source in the details modal", () => {
    render(<DNSQueryRow row={row} ipSpaceName="Corp" />);
    fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
    const text = screen.getByRole("dialog").textContent ?? "";
    expect(text).toContain("laptop-7");
    expect(text).toContain("from IP space Corp");
  });

  it("says reverse DNS for a PTR name", () => {
    render(<DNSQueryRow row={{ ...row, client_name_source: "ptr" }} />);
    fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
    expect(screen.getByRole("dialog").textContent).toContain(
      "from reverse DNS",
    );
  });
});

describe("toggle + source (#4249)", () => {
  async function mount() {
    dnsQueries.mockResolvedValue({
      server_id: "s",
      group_id: null,
      server_ids: ["s"],
      events: [row],
      truncated: false,
    });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <DNSQueriesTab
          sources={[
            {
              server_id: "s",
              server_name: "ns1",
              server_kind: "dns",
              driver: "bind9",
              host: "192.0.2.1",
            },
          ]}
        />
      </QueryClientProvider>,
    );
    await screen.findByText("laptop-7");
  }

  it("sends nothing by default, then ptr, then the chosen space", async () => {
    await mount();
    expect(dnsQueries.mock.calls[0][0].resolve_clients).toBeUndefined();

    fireEvent.click(screen.getByLabelText("Resolve client names"));
    await waitFor(() =>
      expect(dnsQueries.mock.calls.at(-1)![0].resolve_clients).toBe("ptr"),
    );
    expect(sessionStorage.getItem("logs-dns-resolve-clients")).toBe("true");

    await screen.findByText("IP space: Corp");
    fireEvent.change(screen.getByLabelText("Client name source"), {
      target: { value: "sp-1" },
    });
    await waitFor(() => {
      const last = dnsQueries.mock.calls.at(-1)![0];
      expect(last.resolve_clients).toBe("ipam");
      expect(last.ip_space_id).toBe("sp-1");
    });
  });
});

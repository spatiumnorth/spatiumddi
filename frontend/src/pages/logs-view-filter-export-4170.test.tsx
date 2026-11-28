/**
 * @vitest-environment jsdom
 *
 * Logs → DNS Queries: a View select listing the group's configured views and a
 * chip naming the active one (#4170), and an Export control that sends the
 * current filters to the export endpoint (#4171).
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
import { dnsApi, logsApi, type AgentLogSource } from "@/lib/api";
import { DNSQueriesTab } from "./LogsPage";
import { ExportControl } from "./logs/DNSQueryFilterControls";

const sources: AgentLogSource[] = [
  {
    server_id: "s1",
    server_name: "ns1",
    server_kind: "dns",
    driver: "bind9",
    host: "192.0.2.1",
    group_id: "g1",
    group_name: "Default",
  },
];

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <DNSQueriesTab sources={sources} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.spyOn(logsApi, "dnsQueries").mockResolvedValue({
    server_id: null,
    group_id: "g1",
    server_ids: ["s1"],
    events: [],
    truncated: false,
  });
  vi.spyOn(logsApi, "dnsQueryAnalytics").mockResolvedValue({
    total_queries: 10,
    top_qnames: [],
    top_clients: [],
    qtype_distribution: [],
    top_views: [{ key: "external", count: 10 }],
    rcode_distribution: [],
  } as never);
  vi.spyOn(dnsApi, "listViews").mockResolvedValue([
    { id: "v1", name: "internal" },
    { id: "v2", name: "external" },
    { id: "v3", name: "guest-no-traffic" },
  ] as never);
  vi.spyOn(logsApi, "exportDnsQueries").mockResolvedValue({
    filename: "x.csv",
    rows: 3,
    truncated: false,
    rowCap: 100000,
  });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("View filter (#4170)", () => {
  it("lists configured views, including ones with no traffic, plus Any", async () => {
    renderTab();
    const select = (await screen.findByLabelText("View")) as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(4));
    expect([...select.options].map((o) => o.textContent)).toEqual([
      "Any",
      "internal",
      "external",
      "guest-no-traffic",
    ]);
  });

  it("choosing a view filters the query, shows a chip, and Clear resets", async () => {
    renderTab();
    const select = await screen.findByLabelText("View");
    await waitFor(() =>
      expect((select as HTMLSelectElement).options.length).toBe(4),
    );
    expect(screen.queryByTestId("active-view-chip")).toBeNull();
    fireEvent.change(select, { target: { value: "guest-no-traffic" } });
    expect(screen.getByTestId("active-view-chip").textContent).toContain(
      "guest-no-traffic",
    );
    await waitFor(() =>
      expect(logsApi.dnsQueries).toHaveBeenLastCalledWith(
        expect.objectContaining({ view: "guest-no-traffic" }),
      ),
    );
    fireEvent.click(screen.getByTitle("Clear all filters"));
    expect(screen.queryByTestId("active-view-chip")).toBeNull();
    expect((screen.getByLabelText("View") as HTMLSelectElement).value).toBe("");
  });

  it("clicking the By view card sets the same filter, chip and select", async () => {
    renderTab();
    const card = await screen.findByTitle(
      'Filter the events grid below by "external"',
    );
    fireEvent.click(card);
    expect(screen.getByTestId("active-view-chip").textContent).toContain(
      "external",
    );
    expect((screen.getByLabelText("View") as HTMLSelectElement).value).toBe(
      "external",
    );
  });
});

describe("Export (#4171)", () => {
  it("sends the current filters to the export endpoint", async () => {
    renderTab();
    const select = await screen.findByLabelText("View");
    await waitFor(() =>
      expect((select as HTMLSelectElement).options.length).toBe(4),
    );
    fireEvent.change(select, { target: { value: "internal" } });
    fireEvent.change(screen.getByPlaceholderText("A / AAAA / MX…"), {
      target: { value: "aaaa" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Export CSV/ }));
    await waitFor(() => expect(logsApi.exportDnsQueries).toHaveBeenCalled());
    expect(logsApi.exportDnsQueries).toHaveBeenCalledWith(
      expect.objectContaining({
        server_id: "s1",
        view: "internal",
        qtype: "AAAA",
      }),
      "csv",
    );
    fireEvent.click(screen.getByRole("button", { name: /Export JSONL/ }));
    await waitFor(() =>
      expect(logsApi.exportDnsQueries).toHaveBeenLastCalledWith(
        expect.anything(),
        "jsonl",
      ),
    );
  });

  it("says so when the export was capped", async () => {
    vi.mocked(logsApi.exportDnsQueries).mockResolvedValue({
      filename: "x.csv",
      rows: 100000,
      truncated: true,
      rowCap: 100000,
    });
    render(<ExportControl params={{}} />);
    fireEvent.click(screen.getByRole("button", { name: /Export CSV/ }));
    const note = await screen.findByRole("status");
    expect(note.textContent).toContain("capped at 100,000");
    expect(note.textContent).toContain("narrow the filter");
  });
});

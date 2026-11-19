/**
 * @vitest-environment jsdom
 *
 * Whole-row details (#4248): a click anywhere on a DNS Queries / DHCP
 * Activity row opens the details modal, Enter / Space on the focused
 * row too; a selection-drag or a click on an inner control does not.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { DHCPActivityLogRow, DNSQueryLogRow } from "@/lib/api";
import { DHCPActivityRow, DNSQueryRow } from "./LogsPage";
import { formatClientEndpoint } from "@/lib/clientEndpoint";

afterEach(cleanup);

const LONG_QNAME =
  "a-very-long-label-that-overflows-the-qname-column.mail-ads.google.com.example.internal.";
const LONG_RAW =
  "20-Oct-2026 09:12:33.123 queries: info: client @0x7f0000000000 192.0.2.5#53123 (" +
  LONG_QNAME +
  "): view internal: query: " +
  LONG_QNAME +
  " IN AAAA +E(0)K (192.0.2.1)";

const dnsRow = (over: Partial<DNSQueryLogRow> = {}): DNSQueryLogRow => ({
  id: 1,
  ts: "2026-10-20T09:12:33.123Z",
  server_id: "11111111-1111-1111-1111-111111111111",
  server_name: "ns1",
  client_ip: "192.0.2.5",
  client_port: 53123,
  qname: LONG_QNAME,
  qclass: "IN",
  qtype: "AAAA",
  flags: "+E(0)K",
  view: "internal",
  rcode: "NOERROR",
  answer_count: 2,
  raw: LONG_RAW,
  ...over,
});

const dhcpRow = (
  over: Partial<DHCPActivityLogRow> = {},
): DHCPActivityLogRow => ({
  id: 7,
  ts: "2026-10-20T09:12:33.123Z",
  server_id: "22222222-2222-2222-2222-222222222222",
  server_name: "kea1",
  severity: "INFO",
  code: "DHCP4_LEASE_ALLOC",
  mac_address: "aa:bb:cc:dd:ee:ff",
  ip_address: "192.0.2.10",
  transaction_id: "0x1a2b3c4d",
  raw: "INFO  [kea-dhcp4.leases/1234] DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1a2b3c4d: lease 192.0.2.10 has been allocated for 4000 seconds",
  ...over,
});

function selectText(text: string) {
  vi.spyOn(window, "getSelection").mockReturnValue({
    toString: () => text,
  } as unknown as Selection);
}

afterEach(() => vi.restoreAllMocks());

describe.each([
  [
    "DNS query",
    () => <DNSQueryRow row={dnsRow()} />,
    /^Details for .*AAAA from 192\.0\.2\.5 \(press Enter/,
  ],
  [
    "DHCP activity",
    () => <DHCPActivityRow row={dhcpRow()} />,
    /^Details for DHCP4_LEASE_ALLOC/,
  ],
])("%s row (#4248)", (_n, make, name) => {
  it("opens from a click on a cell", () => {
    const { container } = render(make());
    const cell = container.querySelector("span.font-mono") as HTMLElement;
    fireEvent.click(cell);
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("opens on Enter and Space and returns focus to the row on close", () => {
    render(make());
    const row = screen.getByRole("group", { name });
    row.focus();
    fireEvent.keyDown(row, { key: "Enter" });
    expect(screen.getByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(document.activeElement ?? row, { key: "Escape" });
    cleanup();
    render(make());
    const row2 = screen.getByRole("group", { name });
    fireEvent.keyDown(row2, { key: " " });
    expect(screen.getByRole("dialog")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /close/i }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(row2);
  });

  it("the row has no interactive role (it holds the arrow button)", () => {
    render(make());
    expect(screen.getByRole("group", { name }).getAttribute("tabindex")).toBe(
      "0",
    );
    expect(screen.getAllByRole("button")).toHaveLength(1);
  });

  it("the arrow still opens it (once)", () => {
    render(make());
    fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
  });

  it("a click that ended a text selection does not open it", () => {
    const { container } = render(make());
    selectText("some text");
    fireEvent.click(container.querySelector("span.font-mono") as HTMLElement);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

it("a click on an inner control does not open the row's modal", () => {
  const { container } = render(<DNSQueryRow row={dnsRow()} />);
  const inner = document.createElement("button");
  container.firstElementChild!.appendChild(inner);
  fireEvent.click(inner);
  expect(screen.queryByRole("dialog")).toBeNull();
});

describe("client endpoint display (#4248)", () => {
  it("formats IPv4, IPv6, no-port and IPv4-mapped", () => {
    expect(formatClientEndpoint("192.0.2.1", 56028)).toBe("192.0.2.1:56028");
    expect(formatClientEndpoint("2001:db8::1", 56028)).toBe(
      "[2001:db8::1]:56028",
    );
    expect(formatClientEndpoint("2001:db8::1", null)).toBe("2001:db8::1");
    expect(formatClientEndpoint("192.0.2.1")).toBe("192.0.2.1");
    expect(formatClientEndpoint("::ffff:192.0.2.1", 53)).toBe("192.0.2.1:53");
  });

  it("modal shows ip:port, raw line keeps BIND's ip#port, filter sends the address", () => {
    const onFilterClient = vi.fn();
    render(
      <DNSQueryRow
        row={dnsRow({
          client_ip: "2001:db8::1",
          client_port: 56028,
          raw: "client 2001:db8::1#56028 q",
        })}
        onFilterClient={onFilterClient}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog.textContent).toContain("[2001:db8::1]:56028");
    expect(screen.getByTestId("raw-line").textContent).toContain(
      "2001:db8::1#56028",
    );
    fireEvent.click(screen.getByRole("button", { name: /filter by client/i }));
    expect(onFilterClient).toHaveBeenCalledWith("2001:db8::1");
  });
});

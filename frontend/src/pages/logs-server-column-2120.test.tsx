/**
 * @vitest-environment jsdom
 *
 * Logs → DNS Queries / DHCP Activity across servers (#2120). A group or
 * "All servers" read merges several servers' rows, so each row must say
 * which server logged it: a Server column when the read covers more than
 * one server, and the server's name in the row details modal always.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { DHCPActivityLogRow, DNSQueryLogRow } from "@/lib/api";
import { DHCPActivityRow, DNSQueryRow } from "./LogsPage";

afterEach(cleanup);

const dnsRow: DNSQueryLogRow = {
  id: 1,
  ts: "2026-10-20T09:12:33.123Z",
  server_id: "11111111-1111-1111-1111-111111111111",
  server_name: "dns-bind9-ns3-0",
  client_ip: "192.0.2.5",
  client_port: 53123,
  qname: "foo.example.com",
  qclass: "IN",
  qtype: "A",
  flags: "+",
  view: null,
  rcode: "NOERROR",
  answer_count: 1,
  raw: "query: foo.example.com IN A",
};

const dhcpRow: DHCPActivityLogRow = {
  id: 7,
  ts: "2026-10-20T09:12:33.123Z",
  server_id: "22222222-2222-2222-2222-222222222222",
  server_name: "kea-b",
  severity: "INFO",
  code: "DHCP4_LEASE_ALLOC",
  mac_address: "aa:bb:cc:dd:ee:ff",
  ip_address: "192.0.2.10",
  transaction_id: "0x1",
  raw: "DHCP4_LEASE_ALLOC",
};

describe("Server column (#2120)", () => {
  it("shows the server on a DNS row only when asked", () => {
    const { rerender } = render(<DNSQueryRow row={dnsRow} />);
    expect(screen.queryByText("dns-bind9-ns3-0")).toBeNull();
    rerender(<DNSQueryRow row={dnsRow} showServer />);
    expect(screen.getByText("dns-bind9-ns3-0")).toBeTruthy();
  });

  it("shows the server on a DHCP row only when asked", () => {
    const { rerender } = render(<DHCPActivityRow row={dhcpRow} />);
    expect(screen.queryByText("kea-b")).toBeNull();
    rerender(<DHCPActivityRow row={dhcpRow} showServer />);
    expect(screen.getByText("kea-b")).toBeTruthy();
  });

  it("names the server in the details modal", () => {
    render(<DNSQueryRow row={dnsRow} />);
    fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog.textContent).toContain("dns-bind9-ns3-0");
  });
});

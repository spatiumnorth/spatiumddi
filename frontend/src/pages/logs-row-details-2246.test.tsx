/**
 * @vitest-environment jsdom
 *
 * Logs row details (#2246). The DNS Queries and DHCP Activity grids
 * truncate client / qname / raw to one line, and the only way to read
 * the rest was a hover `title` — not selectable, not usable on touch,
 * clipped for long lines. Each row now has a details button that opens
 * every field untruncated.
 *
 * The result wording is pinned too, because it is the one place a
 * detail view could quietly say something the grid does not: a null
 * rcode must read "not recorded" (never NOERROR — response logging was
 * off, #914), and NOERROR with zero answers is NODATA.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import type { DHCPActivityLogRow, DNSQueryLogRow } from "@/lib/api";
import { DHCPActivityRow, DNSQueryRow } from "./LogsPage";

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

function openDetails() {
  fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
  return screen.getByRole("dialog");
}

describe("DNS query row details (#2246)", () => {
  it("opens a modal from the row's details button", () => {
    render(<DNSQueryRow row={dnsRow()} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    const dialog = openDetails();
    expect(dialog.textContent).toContain("DNS query details");
  });

  it("renders the full qname and raw line, untruncated", () => {
    render(<DNSQueryRow row={dnsRow()} />);
    const dialog = openDetails();
    expect(screen.getByTestId("raw-line").textContent).toBe(LONG_RAW);
    expect(dialog.textContent).toContain(LONG_QNAME);
    expect(dialog.textContent).toContain("192.0.2.5#53123");
    expect(dialog.textContent).toContain("internal");
    expect(dialog.textContent).toContain("2026-10-20T09:12:33.123Z");
  });

  it("reads 'not recorded' for a null rcode, never NOERROR", () => {
    render(<DNSQueryRow row={dnsRow({ rcode: null, answer_count: null })} />);
    openDetails();
    const result = screen.getByTestId("dns-result");
    expect(result.textContent).toBe("not recorded");
    expect(result.textContent).not.toContain("NOERROR");
  });

  it("reads NODATA for NOERROR with zero answers", () => {
    render(<DNSQueryRow row={dnsRow({ rcode: "NOERROR", answer_count: 0 })} />);
    openDetails();
    expect(screen.getByTestId("dns-result").textContent).toBe("NODATA");
  });

  it("keeps a real rcode as itself", () => {
    render(
      <DNSQueryRow row={dnsRow({ rcode: "NXDOMAIN", answer_count: 0 })} />,
    );
    openDetails();
    expect(screen.getByTestId("dns-result").textContent).toBe("NXDOMAIN");
  });

  it("copies the raw line and shows a transient Copied", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    Object.defineProperty(window, "isSecureContext", {
      value: true,
      configurable: true,
    });
    render(<DNSQueryRow row={dnsRow()} />);
    openDetails();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    });
    expect(writeText).toHaveBeenCalledWith(LONG_RAW);
    expect(screen.getByRole("button", { name: /copied/i })).toBeTruthy();
  });

  it("copies on plain http, where navigator.clipboard is undefined", async () => {
    Object.defineProperty(navigator, "clipboard", {
      value: undefined,
      configurable: true,
    });
    Object.defineProperty(window, "isSecureContext", {
      value: false,
      configurable: true,
    });
    const execCommand = vi.fn().mockReturnValue(true);
    Object.defineProperty(document, "execCommand", {
      value: execCommand,
      configurable: true,
    });
    render(<DNSQueryRow row={dnsRow()} />);
    openDetails();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    });
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(screen.getByRole("button", { name: /copied/i })).toBeTruthy();
  });

  it("filter buttons set the filter and close the modal", () => {
    const onFilterClient = vi.fn();
    const onFilterQname = vi.fn();
    render(
      <DNSQueryRow
        row={dnsRow()}
        onFilterClient={onFilterClient}
        onFilterQname={onFilterQname}
      />,
    );
    openDetails();
    fireEvent.click(screen.getByRole("button", { name: "Filter by client" }));
    expect(onFilterClient).toHaveBeenCalledWith("192.0.2.5");
    expect(screen.queryByRole("dialog")).toBeNull();
    openDetails();
    fireEvent.click(screen.getByRole("button", { name: "Filter by qname" }));
    expect(onFilterQname).toHaveBeenCalledWith(LONG_QNAME);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("DHCP activity row details (#2246)", () => {
  it("opens a modal with every field and the full raw line", () => {
    const row = dhcpRow();
    render(<DHCPActivityRow row={row} />);
    const dialog = openDetails();
    expect(dialog.textContent).toContain("DHCP activity details");
    for (const v of [
      "INFO",
      "DHCP4_LEASE_ALLOC",
      "aa:bb:cc:dd:ee:ff",
      "192.0.2.10",
      "0x1a2b3c4d",
    ]) {
      expect(dialog.textContent).toContain(v);
    }
    expect(screen.getByTestId("raw-line").textContent).toBe(row.raw);
  });
});

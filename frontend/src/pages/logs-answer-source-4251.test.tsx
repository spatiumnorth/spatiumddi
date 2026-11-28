/**
 * @vitest-environment jsdom
 *
 * DNS query details: how the answer was produced (#4251). A null source
 * must read "not reported" (BIND9 never says), never a guessed value.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { DNSQueryLogRow } from "@/lib/api";
import { DNSQueryRow } from "./LogsPage";

afterEach(cleanup);

const row = (over: Partial<DNSQueryLogRow> = {}): DNSQueryLogRow => ({
  id: 1,
  ts: "2026-11-18T09:12:33.123Z",
  server_id: "11111111-1111-1111-1111-111111111111",
  server_name: "ns1",
  client_ip: "192.0.2.5",
  client_port: 53123,
  qname: "www.example.com",
  qclass: "IN",
  qtype: "A",
  flags: null,
  view: null,
  rcode: null,
  answer_count: null,
  answer_source: null,
  answer_upstream: null,
  raw: "raw",
  ...over,
});

function open() {
  fireEvent.click(screen.getByRole("button", { name: "Show row details" }));
  return screen.getByTestId("dns-answer-source");
}

describe("DNS answer source in details (#4251)", { timeout: 30000 }, () => {
  it("says not reported when the server did not report one", () => {
    render(<DNSQueryRow row={row()} />);
    const el = open();
    expect(el.textContent).toBe("not reported");
  });

  it("shows a reported source", () => {
    render(<DNSQueryRow row={row({ answer_source: "cache" })} />);
    expect(open().textContent).toBe("Cache");
  });

  it("shows the upstream for a forwarded answer", () => {
    render(
      <DNSQueryRow
        row={row({ answer_source: "forwarded", answer_upstream: "1.1.1.1" })}
      />,
    );
    expect(open().textContent).toBe("Forwarded via 1.1.1.1");
  });
});

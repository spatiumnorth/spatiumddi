/**
 * @vitest-environment jsdom
 *
 * Logs → DNS Queries: the analytics strip can follow the grid's filters
 * (#4072), and says so in its header when it does.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { DNSQueryAnalyticsResponse } from "@/lib/api";
import { DNSQueryAnalyticsStrip } from "./LogsPage";
import {
  analyticsFilterParams,
  describeAnalyticsFilters,
} from "./logs/analyticsFilters";

afterEach(cleanup);

const blank = { q: "", qtype: "", client_ip: "", view: "", rcode: "" };
const data = {
  total_queries: 1240,
  top_qnames: [],
  top_clients: [],
  qtype_distribution: [],
  top_views: [],
  rcode_distribution: [],
} as unknown as DNSQueryAnalyticsResponse;

describe("analyticsFilterParams", () => {
  it("sends nothing while the toggle is off", () => {
    expect(
      analyticsFilterParams(false, { ...blank, client_ip: "192.0.2.0/24" }),
    ).toEqual({});
  });
  it("sends the non-blank filters, trimmed, when on", () => {
    expect(
      analyticsFilterParams(true, {
        ...blank,
        client_ip: " 192.0.2.0/24 ",
        qtype: "AAAA",
      }),
    ).toEqual({ client_ip: "192.0.2.0/24", qtype: "AAAA" });
  });
});

describe("strip", () => {
  const props = {
    analytics: data,
    loading: false,
    onPickQname: vi.fn(),
    onPickClient: vi.fn(),
    onPickQtype: vi.fn(),
    onPickView: vi.fn(),
    onPickRcode: vi.fn(),
  };

  it("names the filters it is showing", () => {
    const label = describeAnalyticsFilters({
      client_ip: "192.0.2.0/24",
      qtype: "AAAA",
    });
    render(
      <DNSQueryAnalyticsStrip
        {...props}
        followFilters
        onToggleFollow={vi.fn()}
        filterLabel={label}
      />,
    );
    expect(
      screen.getByText("192.0.2.0/24 · AAAA · 1,240 queries"),
    ).toBeTruthy();
  });

  it("keeps the whole-window wording when unfiltered, and toggles", () => {
    const onToggle = vi.fn();
    render(
      <DNSQueryAnalyticsStrip
        {...props}
        followFilters={false}
        onToggleFollow={onToggle}
        filterLabel=""
      />,
    );
    expect(screen.getByText("1,240 queries in window")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Analytics follow filters"));
    expect(onToggle).toHaveBeenCalledWith(true);
  });
});

/**
 * @vitest-environment jsdom
 *
 * DNS import review panel — the apex NS choice (#1892).
 *
 * An imported zone keeps the source server's apex NS, which the group's
 * agents then serve as the zone's NS set. The commit API takes
 * `apex_ns_policy: "replace"` to swap it for the group's own servers, but an
 * option the review panel never shows is unreachable from the product. These
 * render the real panel: the choice appears only for a zone the preview
 * flagged, it starts unticked (an outside NS can be deliberate), and what is
 * ticked is what the commit sends.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { DNSImportPreview, DNSImportedZone } from "@/lib/api";
import { PreviewPanel } from "./DNSImportPage";

afterEach(cleanup);

function zone(name: string, foreign: string[]): DNSImportedZone {
  return {
    name,
    zone_type: "primary",
    kind: "forward",
    soa: null,
    records: [],
    view_name: null,
    forwarders: [],
    skipped_record_types: {},
    parse_warnings: [],
    foreign_apex_ns: foreign,
  };
}

function preview(zones: DNSImportedZone[]): DNSImportPreview {
  return {
    source: "technitium",
    zones,
    conflicts: [],
    warnings: [],
    total_records: 0,
    record_type_histogram: {},
  } as unknown as DNSImportPreview;
}

function renderPanel(p: DNSImportPreview) {
  const onCommit = vi.fn();
  render(
    <PreviewPanel
      preview={p}
      decisions={{}}
      setDecisions={() => {}}
      conflictByZone={new Map()}
      onCommit={onCommit}
      committing={false}
      onReset={() => {}}
    />,
  );
  return onCommit;
}

const commitButton = () =>
  screen.getByRole("button", { name: /commit import/i });

describe("PreviewPanel apex NS choice (#1892)", () => {
  it("is absent when no zone names an NS outside the group", () => {
    const onCommit = renderPanel(preview([zone("example.com.", [])]));
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByText(/apex NS outside/i)).toBeNull();
    fireEvent.click(commitButton());
    expect(onCommit).toHaveBeenCalledWith("keep");
  });

  it("lists the flagged zone and its hosts, unticked, and keeps by default", () => {
    const onCommit = renderPanel(
      preview([
        zone("example.com.", ["tech1.old.net"]),
        zone("other.com.", []),
      ]),
    );
    expect(screen.getByText(/apex NS outside the target group/i)).toBeTruthy();
    expect(screen.getByText("example.com. → tech1.old.net")).toBeTruthy();
    expect(screen.queryByText(/other\.com\. →/)).toBeNull();
    const box = screen.getByRole("checkbox") as HTMLInputElement;
    expect(box.checked).toBe(false);
    fireEvent.click(commitButton());
    expect(onCommit).toHaveBeenCalledWith("keep");
  });

  it("sends replace once the operator ticks it", () => {
    const onCommit = renderPanel(
      preview([zone("example.com.", ["tech1.old.net"])]),
    );
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(commitButton());
    expect(onCommit).toHaveBeenCalledWith("replace");
  });
});

describe("PreviewPanel zone notes (#3097)", () => {
  it("shows the text of each zone's parse warnings", () => {
    const z = {
      ...zone("example.com.", []),
      parse_warnings: ["Skipped 2 DNSSEC records.", "Line 14: bad TTL."],
    };
    renderPanel(preview([z]));
    const list = screen.getByRole("list", { name: "Notes for example.com." });
    expect(list.textContent).toContain("Skipped 2 DNSSEC records.");
    expect(list.textContent).toContain("Line 14: bad TTL.");
  });

  it("shows no notes list for a zone without warnings", () => {
    renderPanel(preview([zone("example.com.", [])]));
    expect(screen.queryByRole("list", { name: /^Notes for/ })).toBeNull();
  });
});

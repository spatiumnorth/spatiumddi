/**
 * @vitest-environment jsdom
 *
 * Spreadsheet import of a zone's records (#2139). A replace deletes records
 * the sheet does not list, so Import stays disabled until the zone's name is
 * typed back; and a preview with row errors cannot be committed.
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
import type { DNSSheetImportPreview, DNSZone } from "@/lib/api";
import { confirmsZone } from "@/lib/dnsNames";

let nextPreview: DNSSheetImportPreview;
const preview = vi.fn(() => Promise.resolve(nextPreview));
let nextCommit: Record<string, unknown> = {};
const commit = vi.fn(() => Promise.resolve(nextCommit));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      importZoneSheetPreview: () => preview(),
      importZoneSheetCommit: (...args: unknown[]) =>
        (commit as (...a: unknown[]) => Promise<unknown>)(...args),
    },
  };
});

const { ZoneSpreadsheetImportModal } =
  await import("./ZoneSpreadsheetImportModal");

function basePreview(over: Partial<DNSSheetImportPreview> = {}) {
  return {
    zone_id: "z1",
    zone_name: "example.com.",
    format: "csv",
    mode: "replace",
    row_count: 1,
    examples_ignored: 0,
    to_create: [],
    to_update: [],
    to_delete: [
      {
        row: null,
        op: "delete",
        name: "old",
        record_type: "A",
        value: "192.0.2.1",
        ttl: null,
        priority: null,
        weight: null,
        port: null,
        view: null,
        comment: null,
        existing_id: "r1",
        changed_fields: [],
        read_only: false,
      },
    ],
    unchanged: [],
    errors: [],
    skipped: [],
    ...over,
  } as DNSSheetImportPreview;
}

function open(onClose: () => void = () => {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ZoneSpreadsheetImportModal
        groupId="g1"
        zone={{ id: "z1", name: "example.com." } as DNSZone}
        onClose={onClose}
      />
    </QueryClientProvider>,
  );
  const file = new File(["name,type,value\n"], "r.csv", { type: "text/csv" });
  const input = document.querySelector(
    'input[type="file"]',
  ) as HTMLInputElement;
  fireEvent.change(input, { target: { files: [file] } });
}

afterEach(() => {
  cleanup();
  preview.mockClear();
  commit.mockClear();
  nextCommit = {};
});

describe("confirmsZone", () => {
  it("ignores the trailing dot and case", () => {
    expect(confirmsZone("Example.COM", "example.com.")).toBe(true);
    expect(confirmsZone("example.com.", "example.com.")).toBe(true);
    expect(confirmsZone("", "example.com.")).toBe(false);
    expect(confirmsZone("example.org", "example.com.")).toBe(false);
  });
});

describe("spreadsheet import modal (#2139)", () => {
  it("needs the zone name typed back before a replace", async () => {
    nextPreview = basePreview();
    open();
    fireEvent.change(screen.getByRole("combobox"), {
      target: { value: "replace" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(screen.getByText(/Delete \(1\)/)).toBeTruthy());
    const importBtn = screen.getByRole("button", { name: "Import" });
    expect((importBtn as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("Confirm zone name"), {
      target: { value: "example.com" },
    });
    expect((importBtn as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(importBtn);
    await waitFor(() => expect(commit).toHaveBeenCalledTimes(1));
    expect(commit.mock.calls[0]).toEqual([
      "g1",
      "z1",
      expect.any(File),
      "replace",
      "example.com",
    ]);
  });

  it("shows row errors and refuses to commit them", async () => {
    nextPreview = basePreview({
      mode: "merge",
      to_delete: [],
      errors: [
        {
          row: 3,
          reason: "A record value must be a single IPv4 address",
          name: "bad",
          record_type: "A",
          value: "x",
        },
      ],
    });
    open();
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(screen.getByText("Row 3")).toBeTruthy());
    expect(
      (screen.getByRole("button", { name: "Import" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("keeps the modal open to show a provider warning (#1538)", async () => {
    nextPreview = basePreview({
      mode: "merge",
      to_delete: [],
      to_create: [{ ...basePreview().to_delete[0], op: "create", row: 2 }],
    });
    nextCommit = { provider_warning: "Route 53 refused the change" };
    const onClose = vi.fn();
    open(onClose);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(screen.getByText(/Create \(1\)/)).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toMatch(
        /Route 53 refused the change/,
      ),
    );
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Import" })).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Import" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("closes after a clean commit", async () => {
    nextPreview = basePreview({
      mode: "merge",
      to_delete: [],
      to_create: [{ ...basePreview().to_delete[0], op: "create", row: 2 }],
    });
    const onClose = vi.fn();
    open(onClose);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(screen.getByText(/Create \(1\)/)).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });
});

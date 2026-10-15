/**
 * @vitest-environment jsdom
 *
 * Delete Zone says what the delete does (#1880).
 *
 * The dialog said the zone and its records were "permanently deleted" while
 * the console sends the soft delete and the zone goes to Trash. These tests
 * walk both dialogs to their confirm step, read what an operator reads, and
 * check the request dnsApi.deleteZone really sends.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api, dnsApi } from "@/lib/api";
import { BulkDeleteZonesDialog, DeleteZoneDialog } from "./ZoneDeleteDialogs";

afterEach(cleanup);

function text(): string {
  return document.body.textContent ?? "";
}

describe("Delete Zone dialog", () => {
  it("says Trash and restorable, never permanent, at both steps", () => {
    const onConfirm = vi.fn();
    render(
      <DeleteZoneDialog
        zoneName="example.com"
        onConfirm={onConfirm}
        onClose={() => {}}
      />,
    );
    expect(text()).toMatch(/Trash/);
    expect(text()).toMatch(/restore/i);
    expect(text()).not.toMatch(/permanent/i);

    fireEvent.click(screen.getByText("Continue"));
    expect(text()).toMatch(/Move Zone to Trash/);
    expect(text()).toMatch(/restore/i);
    expect(text()).not.toMatch(/permanent/i);
    expect(text()).not.toMatch(/cannot be undone/i);

    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByText("Move to Trash"));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

describe("bulk zone delete dialog", () => {
  it("says Trash and restorable, never permanent", () => {
    render(
      <BulkDeleteZonesDialog
        count={3}
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    expect(text()).toMatch(/Trash/);
    fireEvent.click(screen.getByText("Continue"));
    expect(text()).toMatch(
      /3 zones and all their records will be moved to Trash/,
    );
    expect(text()).toMatch(/restore/i);
    expect(text()).not.toMatch(/permanent/i);
  });
});

describe("the request the dialogs send", () => {
  it("is the soft delete: no permanent flag", async () => {
    let seen: { method?: string; url?: string; params?: unknown } = {};
    const adapter = vi.fn((config) => {
      seen = config;
      return Promise.resolve({
        data: {},
        status: 204,
        statusText: "",
        headers: {},
        config,
      });
    });
    const original = api.defaults.adapter;
    api.defaults.adapter = adapter as never;
    try {
      await dnsApi.deleteZone("g1", "z1");
    } finally {
      api.defaults.adapter = original;
    }
    expect(seen.method).toBe("delete");
    expect(seen.url).toBe("/dns/groups/g1/zones/z1");
    expect(JSON.stringify(seen.params ?? {})).not.toMatch(/permanent/);
    expect(seen.url).not.toMatch(/permanent/);
  });
});

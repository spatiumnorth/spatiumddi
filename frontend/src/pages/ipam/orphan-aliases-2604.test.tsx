/**
 * @vitest-environment jsdom
 *
 * Mark as Orphan says what happens to the address's DNS aliases (#2604).
 *
 * The option is called reversible, and the alias help said the aliases last
 * until the IP is purged, while orphaning deleted them for good and Restore
 * brought back the host record only. The backend now withdraws the aliases
 * and Restore publishes them again; these tests read what the operator
 * reads, on the dialog and in both alias help lines.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { DeleteOrOrphanModal } from "./IPAMPage";
import type { IPAddress } from "@/lib/api";

afterEach(cleanup);

const address = {
  id: "00000000-0000-0000-0000-000000000001",
  address: "10.98.3.21",
  status: "allocated",
} as unknown as IPAddress;

describe("Mark as Orphan and the address's DNS aliases (#2604)", () => {
  it("says the aliases leave the zone and come back on restore", () => {
    render(
      <DeleteOrOrphanModal
        address={address}
        onOrphan={() => {}}
        onPurge={() => {}}
        onClose={() => {}}
      />,
    );
    const option = screen.getByText("Mark as Orphan (reversible)")
      .parentElement as HTMLElement;
    const text = option.textContent!.replace(/\s+/g, " ");
    expect(text).toMatch(/aliases leave the zone/);
    expect(text).toMatch(
      /restoring it publishes its DNS records and aliases again/,
    );
  });

  it("the alias help no longer says aliases last until a purge", () => {
    const src = readFileSync(join(__dirname, "IPAMPage.tsx"), "utf8").replace(
      /\s+/g,
      " ",
    );
    expect(
      /(?:removed|Deleted) automatically when the IP is purged/.test(src),
      "an alias help line still says the aliases last until the IP is purged",
    ).toBe(false);
    const helps = src.match(/withdrawn while the IP is an orphan/gi) ?? [];
    expect(helps.length).toBe(2);
  });
});

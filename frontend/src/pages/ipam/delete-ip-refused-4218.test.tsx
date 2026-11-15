/**
 * @vitest-environment jsdom
 *
 * A refused Delete Permanently of an address is announced inside the open
 * "Delete IP Address" dialog (#4218): the banner it used to land in sits
 * behind the aria-modal dialog.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { IPAddress } from "@/lib/api";
import { DeleteOrOrphanModal } from "./IPAMPage";

afterEach(cleanup);

function show(error?: string | null) {
  const address = {
    id: "ip-1",
    address: "10.215.45.20",
    status: "allocated",
    alias_count: 0,
  } as IPAddress;
  render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <DeleteOrOrphanModal
          address={address}
          onOrphan={() => {}}
          onPurge={() => {}}
          onClose={() => {}}
          error={error}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Delete IP Address, a refused delete (#4218)", () => {
  it("announces the server's reason inside the dialog", () => {
    show("E911 location binding(s) still point at it");
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("alert").textContent).toContain(
      "E911 location binding",
    );
  });

  it("shows no alert before a refusal", () => {
    show(null);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

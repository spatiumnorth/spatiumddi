/**
 * @vitest-environment jsdom
 *
 * The DNS Blocklists page reads four things that all need read on `dnsbl`.
 * When the API refuses them the page says so; it never shows an empty
 * catalog, "0 list(s) enabled", "Last sweep never" or "No pinned IPs."
 * over a read that was refused (#2701). A read that answered keeps its
 * empty state.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

let mode: "refused" | "empty" = "refused";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const answer = (empty: unknown) => () =>
    mode === "refused"
      ? Promise.reject({
          response: { status: 403, data: { detail: "need 'read' on 'dnsbl'" } },
        })
      : Promise.resolve(empty);
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: () => Promise.resolve({ is_superadmin: false }),
      myPermissions: () =>
        Promise.resolve({ is_superadmin: false, grants: [] }),
    },
    dnsblApi: {
      ...actual.dnsblApi,
      listLists: answer([]),
      listPinned: answer([]),
      getSettings: answer({
        dnsbl_monitoring_enabled: false,
        dnsbl_check_interval_hours: 24,
        dnsbl_sweep_last_run_at: null,
      }),
      listListings: answer({ items: [], total: 0 }),
    },
  };
});

import { DNSBLPage } from "./DNSBLPage";

afterEach(cleanup);

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DNSBLPage />
    </QueryClientProvider>,
  );
}

describe("DNSBLPage refused reads", () => {
  it("says the reads were refused instead of showing empty/zero/never", async () => {
    mode = "refused";
    show();
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "You don't have permission to see the pinned IPs",
      ),
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("the blocklist catalog");
    expect(text).toContain("the sweep settings");
    expect(text).not.toContain("No pinned IPs.");
    expect(text).not.toContain("0 list(s) enabled");
    expect(text).not.toContain("0 IP-listing(s)");
    expect(text).not.toContain("never");
  });

  it("keeps the empty states over reads that answered", async () => {
    mode = "empty";
    show();
    await waitFor(() => screen.getByText("No pinned IPs."));
    expect(document.body.textContent).toContain("0 list(s) enabled");
    expect(document.body.textContent).toContain("never");
  });
});

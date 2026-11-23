/**
 * @vitest-environment jsdom
 *
 * TldRegistrySection — a failed refresh (#4800). The confirm modal's overlay
 * covered the section's own error banner, so the operator saw the modal sit
 * there and never the reason. The modal closes and the section shows it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", () => ({
  dnsApi: {
    getTldRegistry: vi.fn().mockResolvedValue({
      origin: "bundled",
      version: "1",
      bundled_version: "1",
      snapshot_version: null,
      fetched_at: null,
      age_days: null,
      stale: false,
      count: 1,
    }),
    refreshTldRegistry: vi.fn().mockRejectedValue(new Error("IANA said no")),
  },
  formatApiError: (e: unknown) => (e as Error).message,
}));

import { TldRegistrySection } from "./TldRegistrySection";

afterEach(cleanup);

describe("TldRegistrySection", () => {
  it("closes the confirm modal and shows the error on the section", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <TldRegistrySection isSuperadmin />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByText("Refresh now"));
    fireEvent.click(await screen.findByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("IANA said no")).toBeTruthy();
    expect(screen.queryByText("Refresh the TLD registry?")).toBeNull();
  });
});

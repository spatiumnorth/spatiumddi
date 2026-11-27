/**
 * @vitest-environment jsdom
 *
 * #4799 — an install with no route to GitHub is told so, not blamed on
 * rate limiting.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const list = vi.fn();
vi.mock("@/lib/api", async (orig) => ({
  ...(await orig<typeof import("@/lib/api")>()),
  applianceReleasesApi: { list: (...a: unknown[]) => list(...a) },
}));

import { ReleasesTab } from "./ReleasesTab";

afterEach(() => {
  cleanup();
  list.mockReset();
});

async function shown(fetch_error: string | null) {
  list.mockResolvedValue({
    installed_version: "1.0.0",
    releases: [],
    fetch_error,
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ReleasesTab />
    </QueryClientProvider>,
  );
  await screen.findByText("No releases found");
  return document.body.textContent ?? "";
}

describe("ReleasesTab empty state", () => {
  it("says GitHub is unreachable, with the air-gap way out", async () => {
    const text = await shown("unreachable");
    expect(text).toContain("GitHub isn't reachable from the control plane");
    expect(text).toContain("Upload image");
    expect(text).not.toMatch(/rate-limit/i);
  });
  it("blames rate limiting only for a real 403 / 429", async () => {
    expect(await shown("rate_limited")).toMatch(/rate-limiting/);
  });
});

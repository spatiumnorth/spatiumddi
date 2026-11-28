/**
 * @vitest-environment jsdom
 *
 * The Security tab's Reachability card (#3651): a verdict is shown WITH its
 * evidence, never bare; exact addresses appear only when the API sent them
 * (superadmin); and with the module off the card neither renders nor asks.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const verdict = vi.fn();
let moduleOn = true;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () =>
        Promise.resolve({ is_superadmin: false, grants: [] }),
    },
    webExposureApi: {
      ...actual.webExposureApi,
      verdict: (...a: unknown[]) => verdict(...a),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => moduleOn }),
}));

import { WebExposureCard } from "./WebExposureCard";
import type { WebExposureVerdict } from "@/lib/api";

afterEach(() => {
  cleanup();
  verdict.mockReset();
  moduleOn = true;
});

const base: WebExposureVerdict = {
  verdict: "exposed",
  severity: "warning",
  window_hours: 24,
  threshold: 3,
  distinct_external_buckets: 3,
  since: "2026-11-14T10:00:00Z",
  totals: { login_page: 6 },
  distinct_usernames: 0,
  attack_evidence: false,
  intentional: false,
  attribution_warning: false,
  deployment_shape: "compose",
  fix_hint: "Bind HTTP_PORT to the LAN interface.",
  summary: "3 outside network(s) reached this install in the last 24 h.",
  buckets: [
    {
      bucket: "203.0.113.0/24",
      requests: 4,
      signals: { login_page: 4 },
      first_seen: "2026-11-14T10:00:00Z",
      last_seen: "2026-11-14T11:00:00Z",
      endpoints: ["/api/v1/settings/public"],
      addresses: ["203.0.113.7"],
      login_page: 4,
      other_api: 0,
      login_failures: 0,
    },
  ],
};

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <WebExposureCard />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

describe("WebExposureCard", () => {
  it("shows the verdict with its evidence and the fix", async () => {
    verdict.mockResolvedValue(base);
    await show();
    expect(screen.getByText("Exposed")).toBeTruthy();
    expect(screen.getByText(/reached this install/)).toBeTruthy();
    expect(screen.getByText("203.0.113.0/24")).toBeTruthy();
    expect(screen.getByText("/api/v1/settings/public")).toBeTruthy();
    expect(screen.getByText(/Bind HTTP_PORT/)).toBeTruthy();
    expect(screen.getByText("203.0.113.7")).toBeTruthy();
  });

  it("withholds addresses the API did not send", async () => {
    verdict.mockResolvedValue({
      ...base,
      buckets: [{ ...base.buckets[0], addresses: null }],
    });
    await show();
    expect(screen.queryByText("203.0.113.7")).toBeNull();
  });

  it("says not observed honestly, with no fix nagging", async () => {
    verdict.mockResolvedValue({
      ...base,
      verdict: "not_observed",
      severity: null,
      buckets: [],
      summary: "No requests from outside your networks. Not proof.",
    });
    await show();
    expect(screen.getByText("Not observed")).toBeTruthy();
    expect(screen.queryByText(/Fix for this deployment/)).toBeNull();
  });

  it("neither renders nor asks while the module is off", async () => {
    moduleOn = false;
    await show();
    expect(verdict).not.toHaveBeenCalled();
    expect(screen.queryByText(/Reachability/)).toBeNull();
  });
});

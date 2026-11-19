/**
 * @vitest-environment jsdom
 *
 * The IPAM tree's utilisation dots and bars draw amber and red from Settings'
 * Warning / Critical Threshold, not from literals (#3327).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const settings = { warn: 50, critical: 95 };
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: {
      get: () =>
        Promise.resolve({
          utilization_warn_threshold: settings.warn,
          utilization_critical_threshold: settings.critical,
        }),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { UtilizationDot, UtilizationBar } = await import("./IPAMPage");

afterEach(cleanup);

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("utilisation thresholds (#3327)", () => {
  it("a dot at 57% is amber once the Warning Threshold is 50", async () => {
    wrap(<UtilizationDot percent={57.14} />);
    const dot = await screen.findByLabelText("57% utilized");
    await vi.waitFor(() => expect(dot.className).toContain("bg-amber-400"));
  });
  it("a bar at 57% is amber once the Warning Threshold is 50", async () => {
    const { container } = wrap(<UtilizationBar percent={57.14} />);
    await vi.waitFor(() =>
      expect(container.querySelector(".bg-amber-400")).not.toBeNull(),
    );
  });
  it("red follows the Critical Threshold", async () => {
    settings.critical = 60;
    wrap(<UtilizationDot percent={61} />);
    const dot = await screen.findByLabelText("61% utilized");
    await vi.waitFor(() => expect(dot.className).toContain("bg-red-500"));
    settings.critical = 95;
  });
  it("below the warning band stays green", async () => {
    wrap(<UtilizationDot percent={40} />);
    const dot = await screen.findByLabelText("40% utilized");
    await new Promise((r) => setTimeout(r, 20));
    expect(dot.className).toContain("bg-green-500");
  });
});

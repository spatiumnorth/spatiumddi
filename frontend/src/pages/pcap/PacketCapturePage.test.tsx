/**
 * @vitest-environment jsdom
 *
 * Packet capture page with the tools.pcap module off (#1311).
 *
 * The route is not module-gated, only the API is, so the Fleet drilldown or a
 * bookmark lands here with the module off. It used to render the full form
 * and fail only on Run with "Feature 'tools.pcap' is disabled". These pin
 * that the page says the feature is off instead, and renders nothing that
 * calls the gated API while it does.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const modules = { ready: true, on: false };

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    ready: modules.ready,
    enabled: (id: string) => (id === "tools.pcap" ? modules.on : true),
  }),
}));

// Any call here would be a gated request the page must not make while the
// module is off.
const apiCalls = vi.fn();
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const trap = new Proxy(
    {},
    {
      get: (_t, name) => () => {
        apiCalls(String(name));
        return new Promise(() => {});
      },
    },
  );
  return { ...actual, pcapApi: trap, applianceApprovalApi: trap };
});

import { PacketCapturePage } from "@/pages/pcap/PacketCapturePage";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter
        initialEntries={["/tools/pcap?vantage=appliance&appliance=x"]}
      >
        <PacketCapturePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  apiCalls.mockReset();
});

describe("PacketCapturePage with tools.pcap off (#1311)", () => {
  it("says the feature is off and where to enable it", () => {
    modules.ready = true;
    modules.on = false;
    renderPage();
    expect(screen.getByText("Packet capture is turned off")).toBeTruthy();
    const link = screen.getByRole("link", { name: "Features & Integrations" });
    expect(link.getAttribute("href")).toBe("/admin/features");
    expect(screen.queryByText("New capture")).toBeNull();
    expect(apiCalls).not.toHaveBeenCalled();
  });

  it("waits for the module list instead of assuming the module is on", () => {
    // enabled() is optimistically true while loading; rendering the tool
    // then would fire the gated history query and 404.
    modules.ready = false;
    modules.on = false;
    renderPage();
    expect(screen.queryByText("New capture")).toBeNull();
    expect(screen.queryByText("Packet capture is turned off")).toBeNull();
    expect(apiCalls).not.toHaveBeenCalled();
  });

  it("renders the tool when the module is on", () => {
    modules.ready = true;
    modules.on = true;
    renderPage();
    expect(screen.getByText("New capture")).toBeTruthy();
    expect(screen.queryByText("Packet capture is turned off")).toBeNull();
  });
});

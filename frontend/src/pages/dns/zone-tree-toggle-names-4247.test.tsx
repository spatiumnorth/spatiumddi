/**
 * @vitest-environment jsdom
 *
 * The zone-tree parent-row toggle and the server-group toggle named neither
 * their row nor their state to a screen reader (#4247).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSZone } from "@/lib/api";

const z = (id: string, name: string) => ({ id, name }) as unknown as DNSZone;
const ZONES = [z("p", "example.com"), z("c", "www.example.com")];
const GROUPS = [{ id: "g1", name: "edge-group", group_type: "internal" }];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listZones: () => Promise.resolve(ZONES),
      listViews: () => Promise.resolve([]),
      listGroups: () => Promise.resolve(GROUPS),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { ZoneTreeRows, DNSPage } = await import("./DNSPage");

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => sessionStorage.clear());
afterEach(cleanup);

describe("tree toggles name their row and state (#4247)", () => {
  it("zone parent row toggle", async () => {
    wrap(
      <ZoneTreeRows
        groupId="g1"
        selectedZoneId={null}
        onSelectZone={() => {}}
      />,
    );
    const btn = await screen.findByRole("button", { name: "Expand com" });
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(btn);
    const open = screen.getByRole("button", { name: "Collapse com" });
    expect(open.getAttribute("aria-expanded")).toBe("true");
    // The child parent row names itself, not its ancestor.
    expect(
      screen
        .getByRole("button", { name: "Expand example.com" })
        .getAttribute("aria-expanded"),
    ).toBe("false");
  });

  it("server group toggle", async () => {
    wrap(<DNSPage />);
    const btn = await screen.findByRole("button", {
      name: "Expand edge-group",
    });
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(btn);
    expect(
      screen
        .getByRole("button", { name: "Collapse edge-group" })
        .getAttribute("aria-expanded"),
    ).toBe("true");
  });
});

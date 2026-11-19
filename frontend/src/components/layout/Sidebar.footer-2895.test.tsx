/**
 * @vitest-environment jsdom
 *
 * The sidebar footer is compact (#2895). The destinations an operator reads by
 * name (Appliance, Features & Integrations, Settings) stay text rows; About,
 * GitHub and Collapse share one row with the version as icon buttons. Every
 * one of them must stay reachable, by keyboard and by accessible name,
 * expanded, collapsed and in the mobile drawer.
 */

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    versionApi: {
      ...actual.versionApi,
      get: () => Promise.resolve({ version: "1.0.0", appliance_mode: false }),
    },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      countPending: () => Promise.resolve({ count: 0 }),
    },
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    publicSettingsApi: {
      ...actual.publicSettingsApi,
      get: () => new Promise(() => {}),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", async () => {
  const actual = await vi.importActual<
    typeof import("@/hooks/useFeatureModules")
  >("@/hooks/useFeatureModules");
  return {
    ...actual,
    useFeatureModules: () => ({ ready: true, enabled: () => true }),
  };
});

import { Sidebar } from "./Sidebar";
import { ALL_NAV_DESTINATIONS } from "@/lib/navigation";

function mount(props: Parameters<typeof Sidebar>[0] = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Sidebar {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  localStorage.removeItem("sidebar-collapsed");
});

afterEach(() => {
  cleanup();
  localStorage.removeItem("sidebar-collapsed");
});

function utilityRow() {
  return screen.getByTestId("sidebar-utility-row");
}

describe("sidebar footer (#2895)", () => {
  it("keeps the main destinations as named text rows", () => {
    mount();
    for (const [name, href] of [
      ["Appliance", "/appliance"],
      ["Features & Integrations", "/admin/features"],
      ["Settings", "/settings"],
    ]) {
      const link = screen.getByRole("link", { name });
      expect(link.getAttribute("href")).toBe(href);
      expect(link.textContent).toBe(name);
    }
  });

  it("puts About, GitHub and Collapse on one row as labelled icons", () => {
    mount();
    const row = utilityRow();

    const about = screen.getByRole("link", { name: "About" });
    expect(about.getAttribute("href")).toBe("/about");
    expect(about.getAttribute("title")).toBe("About");

    const github = screen.getByRole("link", {
      name: "GitHub (opens in a new tab)",
    });
    expect(github.getAttribute("target")).toBe("_blank");

    const collapse = screen.getByRole("button", { name: "Collapse sidebar" });
    expect(collapse.getAttribute("aria-expanded")).toBe("true");

    for (const el of [about, github, collapse]) {
      expect(row.contains(el)).toBe(true);
      // Icon only: the name comes from aria-label, not visible text.
      expect(el.textContent).toBe("");
    }
    // The version shares the row.
    expect(row.textContent).toContain("v");
  });

  it("collapses and expands from the row, and About stays reachable", () => {
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Collapse sidebar" }));

    const expand = screen.getByRole("button", { name: "Expand sidebar" });
    expect(expand.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByRole("link", { name: "About" })).toBeTruthy();
    expect(
      screen.getByRole("link", { name: "GitHub (opens in a new tab)" }),
    ).toBeTruthy();
    expect(screen.getByRole("link", { name: "Settings" })).toBeTruthy();

    fireEvent.click(expand);
    expect(
      screen.getByRole("button", { name: "Collapse sidebar" }),
    ).toBeTruthy();
  });

  it("closes the mobile drawer when About is chosen", () => {
    const onMobileClose = vi.fn();
    mount({ mobileOpen: true, onMobileClose });
    onMobileClose.mockClear();

    fireEvent.click(screen.getByRole("link", { name: "About" }));

    expect(onMobileClose).toHaveBeenCalled();
  });

  it("still lists every footer page in the palette's source", () => {
    const palette = ALL_NAV_DESTINATIONS.map((d) => d.to);
    for (const to of ["/appliance", "/admin/features", "/settings", "/about"]) {
      expect(palette).toContain(to);
    }
  });
});

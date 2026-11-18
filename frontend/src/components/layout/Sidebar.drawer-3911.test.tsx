/**
 * @vitest-environment jsdom
 *
 * #3911: below md the open navigation drawer is a modal dialog: focus moves
 * in and stays in, Esc closes it, and closing gives focus back to Open
 * navigation.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { useState } from "react";

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
import { Header } from "./Header";

// A phone-width viewport: no (min-width: 768px) match.
beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  }));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function Shell() {
  const [open, setOpen] = useState(false);
  return (
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <Sidebar mobileOpen={open} onMobileClose={() => setOpen(false)} />
        <Header onMobileMenu={() => setOpen(true)} mobileNavOpen={open} />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("mobile navigation drawer", () => {
  it("is a named modal dialog, with focus inside and aria-expanded set", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    const open = screen.getByRole("button", { name: "Open navigation" });
    expect(open.getAttribute("aria-expanded")).toBe("false");
    await user.click(open);
    const dialog = screen.getByRole("dialog", { name: "Navigation" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(open.getAttribute("aria-expanded")).toBe("true");
  });

  it("keeps Tab inside the drawer", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    const dialog = screen.getByRole("dialog", { name: "Navigation" });
    for (let i = 0; i < 80; i++) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("Esc closes it and focus returns to Open navigation", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    const open = screen.getByRole("button", { name: "Open navigation" });
    open.focus();
    await user.keyboard("{Enter}");
    await user.keyboard("{Escape}");
    expect(
      screen.queryByRole("button", { name: "Close navigation" }),
    ).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(open);
  });

  it("closing with its Close button returns focus too", async () => {
    const user = userEvent.setup();
    render(<Shell />);
    const open = screen.getByRole("button", { name: "Open navigation" });
    open.focus();
    await user.keyboard("{Enter}");
    await user.click(screen.getByRole("button", { name: "Close navigation" }));
    expect(document.activeElement).toBe(open);
  });
});

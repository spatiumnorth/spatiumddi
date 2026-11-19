/**
 * @vitest-environment jsdom
 *
 * #3231 — every place the console keeps a preference in web storage survives
 * a browser that refuses it, in both forms:
 *
 * - site data blocked: reading ``window.localStorage`` or
 *   ``window.sessionStorage`` throws a ``SecurityError`` (Chrome and Edge);
 * - storage full: the store reads, but every ``setItem`` throws a
 *   ``QuotaExceededError``.
 *
 * The theme (every signed-in page's header), the sidebar's collapse, a
 * module's last URL (IPAM, DNS, DHCP, DNS pools), the dashboard's tab and the
 * fleet's VIP advisory must neither take the page down to "Something went
 * wrong" nor stop working. With storage working, each preference is still
 * kept (controls).
 *
 * The API objects are replaced by recorders that never answer unless a test
 * says otherwise, as in ``dhcp-off-2130.test.tsx``.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

const mods = { off: new Set<string>() };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !mods.off.has(id),
  }),
}));

const { useTheme } = await import("@/hooks/useTheme");
const { useStickyLocation } = await import("@/lib/stickyLocation");
const { Sidebar } = await import("@/components/layout/Sidebar");
const { DashboardPage } = await import("./DashboardPage");
const { FleetTab } = await import("./appliance/FleetTab");

// ── Refusing storage ─────────────────────────────────────────────────────────

type Area = "localStorage" | "sessionStorage";
const AREAS: Area[] = ["localStorage", "sessionStorage"];
const ORIGINAL = Object.fromEntries(
  AREAS.map((area) => [area, Object.getOwnPropertyDescriptor(window, area)!]),
) as Record<Area, PropertyDescriptor>;

/** Site data blocked: the getters themselves throw, as in Chrome and Edge. */
function blockSiteData() {
  for (const area of AREAS) {
    Object.defineProperty(window, area, {
      configurable: true,
      get() {
        throw new DOMException(
          `Failed to read the '${area}' property from 'Window': Access is denied for this document.`,
          "SecurityError",
        );
      },
    });
  }
}

/** Storage full: reads work, every write is refused. */
function fillStorage() {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    throw new DOMException(
      "Failed to execute 'setItem' on 'Storage': Setting the value exceeded the quota.",
      "QuotaExceededError",
    );
  });
}

/** Errors the page let escape: an event handler's throw reaches the window. */
const escaped: unknown[] = [];
const recordEscape = (e: ErrorEvent) => escaped.push(e.error);

let systemDark = false;

beforeEach(() => {
  mods.off = new Set();
  escaped.length = 0;
  window.addEventListener("error", recordEscape);
  systemDark = false;
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: systemDark && query === "(prefers-color-scheme: dark)",
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
  }));
  document.documentElement.classList.remove("dark");
});

afterEach(() => {
  cleanup();
  window.removeEventListener("error", recordEscape);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  for (const area of AREAS) Object.defineProperty(window, area, ORIGINAL[area]);
  localStorage.clear();
  sessionStorage.clear();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

function open(ui: ReactNode, route = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const dark = () => document.documentElement.classList.contains("dark");

// ── The theme ────────────────────────────────────────────────────────────────

describe("the theme (useTheme, in every signed-in page's header)", () => {
  it("follows the system and still toggles with site data blocked", () => {
    systemDark = true;
    blockSiteData();
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("dark");
    expect(dark()).toBe(true);

    act(() => result.current.toggleTheme());
    expect(result.current.theme).toBe("light");
    expect(dark()).toBe(false);
  });

  it("keeps the saved theme and still toggles with storage full", () => {
    localStorage.setItem("theme", "dark");
    fillStorage();
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("dark");
    expect(dark()).toBe(true);

    act(() => result.current.toggleTheme());
    expect(result.current.theme).toBe("light");
    expect(dark()).toBe(false);
  });

  it("saves the chosen theme with storage working (control)", () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("light");
    act(() => result.current.toggleTheme());
    expect(localStorage.getItem("theme")).toBe("dark");
  });
});

// ── A module's last URL ──────────────────────────────────────────────────────

const STICKY_KEY = "spatium.lastUrl.ipam";

function StickyProbe() {
  useStickyLocation(STICKY_KEY);
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <p data-testid="at">{location.pathname + location.search}</p>
      <button type="button" onClick={() => navigate("/ipam?subnet=s2")}>
        Open subnet s2
      </button>
    </>
  );
}

const at = () => screen.getByTestId("at").textContent;
const openSubnet = () =>
  fireEvent.click(screen.getByRole("button", { name: "Open subnet s2" }));

describe("a module's last URL (useStickyLocation)", () => {
  it("opens the bare URL and follows links with site data blocked", () => {
    blockSiteData();
    open(<StickyProbe />, "/ipam");
    expect(at()).toBe("/ipam");
    openSubnet();
    expect(at()).toBe("/ipam?subnet=s2");
    expect(escaped).toEqual([]);
  });

  it("opens a deep link and follows links with storage full", () => {
    fillStorage();
    open(<StickyProbe />, "/ipam?subnet=s1");
    expect(at()).toBe("/ipam?subnet=s1");
    openSubnet();
    expect(at()).toBe("/ipam?subnet=s2");
    expect(escaped).toEqual([]);
  });

  it("restores and saves the last URL with storage working (control)", () => {
    sessionStorage.setItem(STICKY_KEY, "/ipam?subnet=s1");
    open(<StickyProbe />, "/ipam");
    expect(at()).toBe("/ipam?subnet=s1");
    openSubnet();
    expect(sessionStorage.getItem(STICKY_KEY)).toBe("/ipam?subnet=s2");
  });
});

// ── The sidebar ──────────────────────────────────────────────────────────────

function collapseSidebar() {
  fireEvent.click(screen.getByRole("button", { name: "Collapse sidebar" }));
}

describe("the sidebar's collapse (every signed-in page)", () => {
  it("renders and still collapses with site data blocked", () => {
    blockSiteData();
    open(<Sidebar />);
    collapseSidebar();
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
    expect(escaped).toEqual([]);
  });

  it("still collapses with storage full", () => {
    fillStorage();
    open(<Sidebar />);
    collapseSidebar();
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
    expect(escaped).toEqual([]);
  });

  it("remembers the collapse with storage working (control)", () => {
    open(<Sidebar />);
    collapseSidebar();
    expect(localStorage.getItem("sidebar-collapsed")).toBe("true");
  });
});

// ── The dashboard's tab ──────────────────────────────────────────────────────

// The tab bar marks the open tab with ``border-primary``; it carries no
// ``aria-selected``.
const tab = (name: string) => screen.getByRole("button", { name });
const isOpen = (name: string) => tab(name).className.includes("border-primary");

describe("the dashboard's tab", () => {
  it("opens on Overview and switches tabs with site data blocked", async () => {
    blockSiteData();
    open(<DashboardPage />);
    await screen.findByRole("button", { name: "Network" });
    expect(isOpen("Overview")).toBe(true);

    fireEvent.click(tab("Network"));
    expect(isOpen("Network")).toBe(true);
    expect(escaped).toEqual([]);
  });

  it("switches tabs with storage full", async () => {
    fillStorage();
    open(<DashboardPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Network" }));
    expect(isOpen("Network")).toBe(true);
    expect(escaped).toEqual([]);
  });

  it("falls back to Overview from a hidden saved tab with storage full", async () => {
    localStorage.setItem("dashboard-tab", "dhcp");
    mods.off = new Set(["core.dhcp", "dhcp.import"]);
    fillStorage();
    open(<DashboardPage />);
    await waitFor(() => expect(isOpen("Overview")).toBe(true));
    expect(escaped).toEqual([]);
  });

  it("remembers the tab with storage working (control)", async () => {
    open(<DashboardPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Network" }));
    expect(localStorage.getItem("dashboard-tab")).toBe("network");
  });
});

// ── The fleet's VIP advisory ─────────────────────────────────────────────────

const ADVISORY = "Set up a control-plane VIP";

function controlPlaneNode(id: string, hostname: string, role: string) {
  return {
    id,
    hostname,
    state: "approved",
    appliance_variant: "control-plane",
    cluster_role: role,
    capabilities: {},
    assigned_roles: [],
    tags: {},
    port_conflicts: {},
    firewall_state: {},
    role_health: {},
    host_config_health: {},
    host_migration_health: {},
    cluster_health: {},
    storage_findings: [],
  };
}

/** Two approved control-plane nodes and no VIP: the advisory's case. */
function clusterWithoutVip() {
  answer("authApi", "me", () => Promise.resolve({ is_superadmin: true }));
  answer("applianceApprovalApi", "listFleet", () =>
    Promise.resolve({
      appliances: [
        controlPlaneNode("a-1", "cp-1", "primary"),
        controlPlaneNode("a-2", "cp-2", "member"),
      ],
    }),
  );
  answer("applianceApprovalApi", "getMetalLBConfig", () =>
    Promise.resolve({ enabled: false, control_plane_vip: null }),
  );
}

async function dismissAdvisory() {
  await screen.findByText(ADVISORY);
  fireEvent.click(
    screen.getByRole("checkbox", { name: /I understand the risk/ }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
}

describe("the fleet's VIP advisory (Appliance, Fleet)", () => {
  it("shows with site data blocked", async () => {
    clusterWithoutVip();
    blockSiteData();
    open(<FleetTab isApplianceHost />);
    expect(await screen.findByText(ADVISORY)).toBeTruthy();
  });

  it("can be dismissed with storage full", async () => {
    clusterWithoutVip();
    fillStorage();
    open(<FleetTab isApplianceHost />);
    await dismissAdvisory();
    expect(screen.queryByText(ADVISORY)).toBeNull();
    expect(escaped).toEqual([]);
  });

  it("stays dismissed with storage working (control)", async () => {
    clusterWithoutVip();
    open(<FleetTab isApplianceHost />);
    await dismissAdvisory();
    expect(screen.queryByText(ADVISORY)).toBeNull();
    expect(localStorage.getItem("spatium.fleet.vipAdvisoryDismissed")).toBe(
      "1",
    );
  });
});

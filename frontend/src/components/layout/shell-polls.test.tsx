/**
 * @vitest-environment jsdom
 *
 * The app shell asks only the routes its user may read (#1864).
 *
 * The maintenance banner, the first-boot setup banner and the sidebar's
 * approvals badge poll on every page for whoever is signed in. A user without
 * `read` on `appliance` / `approve` on `change_request` was refused each one,
 * and the server writes a `denied` audit row per refusal: about four an
 * minute per open tab, none of them an access attempt the user made. These
 * render the real components against the permission set
 * `GET /auth/me/permissions` returns and count the calls that reach the API.
 */

import { act, cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const calls = {
  info: vi.fn(),
  setup: vi.fn(),
  pending: vi.fn(),
  myPermissions: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    versionApi: {
      ...actual.versionApi,
      get: () => Promise.resolve({ appliance_mode: true }),
    },
    applianceSystemApi: {
      ...actual.applianceSystemApi,
      info: () => calls.info(),
    },
    applianceSetupApi: {
      ...actual.applianceSetupApi,
      state: () => calls.setup(),
    },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      countPending: () => calls.pending(),
    },
    authApi: {
      ...actual.authApi,
      myPermissions: () => calls.myPermissions(),
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

import { MaintenanceBanner } from "./MaintenanceBanner";
import { SetupBanner } from "./SetupBanner";
import { Sidebar } from "./Sidebar";

type Grant = [string, string];

function signInAs(grants: Grant[] | "superadmin") {
  calls.myPermissions.mockResolvedValue(
    grants === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: grants.map(([action, resource_type]) => ({
            action,
            resource_type,
            resource_id: null,
          })),
        },
  );
  calls.info.mockResolvedValue({ maintenance_mode: false });
  calls.setup.mockResolvedValue({ complete: true });
  calls.pending.mockResolvedValue(0);
}

async function mount(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(calls.myPermissions).toHaveBeenCalled());
  // Let the permission answer and the appliance_mode probe land.
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

const EDITOR: Grant[] = [
  ["write", "subnet"],
  ["write", "dns_zone"],
  ["write", "dhcp_scope"],
];

afterEach(() => {
  cleanup();
  for (const f of Object.values(calls)) f.mockReset();
});

describe("a user with no appliance or approval grants", () => {
  it("MaintenanceBanner never asks for the appliance info", async () => {
    signInAs(EDITOR);
    await mount(<MaintenanceBanner />);
    expect(calls.info).not.toHaveBeenCalled();
  });

  it("SetupBanner never asks for the setup state", async () => {
    signInAs(EDITOR);
    await mount(<SetupBanner />);
    expect(calls.setup).not.toHaveBeenCalled();
  });

  it("the sidebar never counts the approval queue", async () => {
    signInAs(EDITOR);
    await mount(<Sidebar />);
    expect(calls.pending).not.toHaveBeenCalled();
  });
});

describe("a user who holds the grants", () => {
  it("MaintenanceBanner asks with read on appliance", async () => {
    signInAs([["read", "appliance"]]);
    await mount(<MaintenanceBanner />);
    expect(calls.info).toHaveBeenCalled();
  });

  it("SetupBanner asks with admin on appliance", async () => {
    signInAs([["admin", "appliance"]]);
    await mount(<SetupBanner />);
    expect(calls.setup).toHaveBeenCalled();
  });

  it("the sidebar counts the queue for an approver", async () => {
    signInAs([["approve", "change_request"]]);
    await mount(<Sidebar />);
    expect(calls.pending).toHaveBeenCalled();
  });

  it("a superadmin is asked all three", async () => {
    signInAs("superadmin");
    await mount(
      <>
        <MaintenanceBanner />
        <SetupBanner />
        <Sidebar />
      </>,
    );
    expect(calls.info).toHaveBeenCalled();
    expect(calls.setup).toHaveBeenCalled();
    expect(calls.pending).toHaveBeenCalled();
  });
});

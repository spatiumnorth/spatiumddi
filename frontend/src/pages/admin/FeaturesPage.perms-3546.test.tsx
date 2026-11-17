/**
 * @vitest-environment jsdom
 *
 * #3546: a module toggle is disabled for a caller who is not a superadmin.
 * While the permissions read is loading or has failed, that is not a role
 * fact, so the tooltip says so rather than "Requires superadmin" (which a
 * superadmin saw).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";

const myPermissions = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { myPermissions: () => myPermissions() },
    featureModulesApi: {
      list: () =>
        Promise.resolve([
          {
            id: "reports.top_n",
            label: "Top-N reports",
            group: "Compliance",
            description: "Top-N reports description",
            default_enabled: true,
            enabled: true,
            requires: [],
          },
        ]),
      toggle: vi.fn(),
      approvalsLock: () =>
        Promise.resolve({ approvals_protect_controls: false }),
    },
  };
});

import { queryClient as appQueryClient } from "@/lib/queryClient";
import {
  PERMISSIONS_CHECKING,
  PERMISSIONS_UNREADABLE,
} from "@/hooks/usePermissions";
import { FeaturesPage } from "./FeaturesPage";

appQueryClient.setQueryDefaults(["my-permissions"], { retry: false });

afterEach(() => {
  cleanup();
  appQueryClient.clear();
  myPermissions.mockReset();
});

async function toggle() {
  render(
    <QueryClientProvider client={appQueryClient}>
      <FeaturesPage />
    </QueryClientProvider>,
  );
  await screen.findByText("Top-N reports description");
  return screen.getByLabelText("Disable Top-N reports");
}

const titleOf = (el: HTMLElement) =>
  el.title || el.closest("[title]")?.getAttribute("title") || "";

describe("a module toggle with unread permissions (#3546)", () => {
  it("says the permissions could not be read when the read failed", async () => {
    myPermissions.mockRejectedValue(new Error("Network Error"));
    const el = await toggle();
    await waitFor(() => expect(titleOf(el)).toBe(PERMISSIONS_UNREADABLE));
  });

  it("says the permissions are being checked while loading", async () => {
    myPermissions.mockReturnValue(new Promise(() => {}));
    const el = await toggle();
    await waitFor(() => expect(titleOf(el)).toBe(PERMISSIONS_CHECKING));
  });

  it("keeps Requires superadmin when the grants are read and say no", async () => {
    myPermissions.mockResolvedValue({
      is_superadmin: false,
      grants: [{ action: "read", resource_type: "*", resource_id: null }],
    });
    const el = await toggle();
    await waitFor(() => expect(titleOf(el)).toBe("Requires superadmin"));
  });

  it("has no tooltip for a superadmin", async () => {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    const el = await toggle();
    await waitFor(() => expect((el as HTMLButtonElement).disabled).toBe(false));
    expect(titleOf(el)).toBe("");
  });
});

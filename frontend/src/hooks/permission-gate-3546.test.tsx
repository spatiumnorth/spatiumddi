/**
 * @vitest-environment jsdom
 *
 * ``permissionGate``'s tooltip while the caller's permissions are unread
 * (#3546): ``can`` is false for everyone then, so the shared "Requires write
 * permission on …" reason would blame the role. The gate says the
 * permissions are being checked, or could not be read, instead, and keeps
 * the caller's reason once grants are read.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";

const myPermissions = vi.fn();
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, authApi: { myPermissions: () => myPermissions() } };
});

import { queryClient } from "@/lib/queryClient";
import {
  PERMISSIONS_CHECKING,
  PERMISSIONS_UNREADABLE,
  permissionGate,
  usePermissions,
} from "./usePermissions";

const REASON = "Requires write permission on subnets";
const KEY = ["my-permissions"];

function WriteButton() {
  const { can } = usePermissions();
  return (
    <button type="button" {...permissionGate(can("write", "subnet"), REASON)}>
      Edit
    </button>
  );
}

function renderButton() {
  queryClient.setQueryDefaults(KEY, { retry: false });
  render(
    <QueryClientProvider client={queryClient}>
      <WriteButton />
    </QueryClientProvider>,
  );
  return screen.getByRole("button", { name: "Edit" });
}

afterEach(() => {
  cleanup();
  queryClient.clear();
  myPermissions.mockReset();
});

describe("permissionGate with unread permissions (#3546)", () => {
  it("says the permissions could not be read when the read failed", async () => {
    myPermissions.mockRejectedValue(new Error("Network Error"));
    const button = renderButton();
    await waitFor(() => expect(button.title).toBe(PERMISSIONS_UNREADABLE));
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it("says the permissions are being checked while the read runs", async () => {
    myPermissions.mockReturnValue(new Promise(() => {}));
    const button = renderButton();
    await waitFor(() => expect(button.title).toBe(PERMISSIONS_CHECKING));
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it("keeps the role reason once the grants are read and lack it", async () => {
    myPermissions.mockResolvedValue({ is_superadmin: false, grants: [] });
    const button = renderButton();
    await waitFor(() => expect(myPermissions).toHaveBeenCalled());
    await waitFor(() => expect(button.title).toBe(REASON));
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it("is open when the grant is held", async () => {
    myPermissions.mockResolvedValue({
      is_superadmin: false,
      grants: [{ action: "write", resource_type: "subnet", resource_id: null }],
    });
    const button = renderButton();
    await waitFor(() =>
      expect((button as HTMLButtonElement).disabled).toBe(false),
    );
    expect(button.title).toBe("");
  });

  it("uses the caller's reason when nothing has asked for the permissions", () => {
    expect(permissionGate(false, REASON)).toEqual({
      disabled: true,
      title: REASON,
    });
  });
});

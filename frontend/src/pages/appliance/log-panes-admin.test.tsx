/**
 * @vitest-environment jsdom
 *
 * Appliance log panes are drawn only for `admin` on `appliance`.
 *
 * Host log files and pod logs (one-shot and streamed) take `admin` on
 * `appliance` server-side. A read-only role keeps the pod list and the
 * self-test, but the log viewer, the diagnostic bundle and the per-pod
 * Logs button are not drawn, and the host log list is never requested.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

let grantedAction = "read";

const listLogs = vi.fn(() => Promise.resolve({ sources: ["syslog"] }));
const listContainers = vi.fn(() =>
  Promise.resolve([
    {
      name: "spatium-api-0",
      image: "ghcr.io/spatiumnorth/spatiumddi-api:dev",
      state: "running",
      status: "Running",
      health: "healthy",
      short_id: "abc123",
      started_at: null,
      is_spatium: true,
    },
  ]),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  return {
    ...actual,
    applianceDiagnosticsApi: {
      ...actual.applianceDiagnosticsApi,
      listLogs,
      tailLog: pending,
    },
    applianceContainersApi: {
      ...actual.applianceContainersApi,
      list: listContainers,
    },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: (action: string, resourceType: string) =>
        resourceType === "appliance" &&
        (grantedAction === action ||
          (grantedAction === "admin" && action === "read")),
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { LogsTab } = await import("@/pages/appliance/LogsTab");
const { ContainersTab } = await import("@/pages/appliance/ContainersTab");

function wrap(node: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  listLogs.mockClear();
  listContainers.mockClear();
});

describe("appliance log panes", () => {
  it("hides the host log viewer from a read-only role", async () => {
    grantedAction = "read";
    wrap(<LogsTab />);
    expect(
      await screen.findByText(/Log text requires admin permission/),
    ).toBeTruthy();
    expect(screen.queryByText("Host log viewer")).toBeNull();
    expect(listLogs).not.toHaveBeenCalled();
  });

  it("shows the host log viewer to an appliance admin", async () => {
    grantedAction = "admin";
    wrap(<LogsTab />);
    expect(await screen.findByText("Host log viewer")).toBeTruthy();
    expect(screen.queryByText(/Log text requires admin permission/)).toBeNull();
    expect(listLogs).toHaveBeenCalled();
  });

  it("hides a pod's Logs button from a read-only role", async () => {
    grantedAction = "read";
    wrap(<ContainersTab />);
    expect(await screen.findByText("spatium-api-0")).toBeTruthy();
    expect(screen.queryByTitle("Stream logs")).toBeNull();
  });

  it("shows a pod's Logs button to an appliance admin", async () => {
    grantedAction = "admin";
    wrap(<ContainersTab />);
    expect(await screen.findByText("spatium-api-0")).toBeTruthy();
    expect(screen.getByTitle("Stream logs")).toBeTruthy();
  });
});

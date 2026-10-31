/**
 * @vitest-environment jsdom
 *
 * #3107 — the Pods list tells a refused read, a failed read and an empty
 * list apart, and a failed refetch does not hide pods it already read.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const listContainers = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
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
      can: () => false,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { ContainersTab } = await import("@/pages/appliance/ContainersTab");
const { shouldRetry } = await import("@/lib/queryClient");

function answered(status: number, detail: string) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    status,
    response: { status, data: { detail } },
  });
}

function wrap() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: shouldRetry, retryDelay: 1 } },
  });
  render(
    <QueryClientProvider client={qc}>
      <ContainersTab />
    </QueryClientProvider>,
  );
  return qc;
}

beforeEach(() => {
  listContainers.mockReset();
});
afterEach(() => {
  cleanup();
});

describe("ContainersTab read states", () => {
  it("says a refused read was refused, not that there are no pods", async () => {
    listContainers.mockRejectedValue(answered(403, "Forbidden"));
    wrap();
    expect(
      await screen.findByText(/don't have permission to see the pods/),
    ).toBeTruthy();
    expect(screen.queryByText(/No pods visible/)).toBeNull();
  });

  it("says a failed read could not be loaded, not refused", async () => {
    listContainers.mockRejectedValue(answered(500, "kubeapi down"));
    wrap();
    expect(await screen.findByText(/Couldn't load the pods/)).toBeTruthy();
    expect(screen.queryByText(/permission/)).toBeNull();
    expect(screen.queryByText(/No pods visible/)).toBeNull();
  });

  it("still says no pods when the list is really empty", async () => {
    listContainers.mockResolvedValue([]);
    wrap();
    expect(await screen.findByText(/No pods visible/)).toBeTruthy();
  });

  it("keeps the pods it read when a later refetch fails", async () => {
    listContainers.mockResolvedValueOnce([
      {
        name: "spatium-api-0",
        short_id: "abc",
        state: "running",
        health: "healthy",
        is_spatium: true,
      },
    ]);
    const qc = wrap();
    expect(await screen.findByText("spatium-api-0")).toBeTruthy();
    listContainers.mockRejectedValue(answered(500, "blip"));
    await qc.refetchQueries({ queryKey: ["appliance", "containers"] });
    await waitFor(() =>
      expect(screen.getByText(/Couldn't load the pods/)).toBeTruthy(),
    );
    expect(screen.getByText("spatium-api-0")).toBeTruthy();
  });
});

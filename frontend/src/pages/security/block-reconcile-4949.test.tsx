/**
 * @vitest-environment jsdom
 *
 * #4949 — a failed Reconcile preview is drawn inside the dialog, not left on
 * "Reading device…" with the error behind the modal.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    blockSyncApi: {
      ...actual.blockSyncApi,
      listTargets: async () => [
        {
          target_kind: "unifi",
          target_id: "t1",
          name: "edge-1",
          block_sync_enabled: true,
          write_credentials_present: true,
        },
      ],
      listBlocks: async () => [],
      reconcile: () => Promise.reject(new Error("device unreachable")),
    },
  };
});

const { BlockSyncPage } = await import("./BlockSyncPage");

afterEach(cleanup);

describe("Reconcile preview failure (#4949)", () => {
  it("shows the error in the dialog and stops loading", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <BlockSyncPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle("Preview + reconcile now"));
    const alert = await screen.findAllByRole("alert");
    expect(alert.length).toBeGreaterThan(0);
    expect(screen.queryByText("Reading device…")).toBeNull();
    const btn = screen.getByRole("button", {
      name: "Reconcile now",
    }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(screen.getByRole("button", { name: "Retry preview" })).toBeTruthy();
  });
});

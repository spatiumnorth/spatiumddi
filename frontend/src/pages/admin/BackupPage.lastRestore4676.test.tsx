/**
 * @vitest-environment jsdom
 *
 * The restore outcome survives the sign-out a restore causes (#4676): the
 * Backup page reads the last outcome back after sign-in, and the sign-in
 * page says why the session ended.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const lastRestore = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ is_superadmin: true }) },
    backupApi: { ...actual.backupApi, lastRestore: () => lastRestore() },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));

import { BackupPage } from "./BackupPage";

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  vi.clearAllMocks();
});

describe("last restore outcome", () => {
  it("shows the safety dump path after signing in again", async () => {
    lastRestore.mockResolvedValue({
      success: true,
      pre_restore_safety_path: "/var/lib/spatiumddi/backups/pre-restore-x.zip",
      duration_ms: 4321,
      manifest: {},
      secrets_payload_keys: [],
      note: "Restore complete. Source archive came from this install.",
      warnings: ["re-publish DS records"],
      performed_at: "2026-11-21T10:00:00Z",
      performed_by: "admin",
    });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <BackupPage />
      </QueryClientProvider>,
    );
    expect(
      await screen.findByText("/var/lib/spatiumddi/backups/pre-restore-x.zip"),
    ).toBeTruthy();
    expect(screen.getByText(/Last restore/)).toBeTruthy();
    expect(screen.getByText("re-publish DS records")).toBeTruthy();
  });
});

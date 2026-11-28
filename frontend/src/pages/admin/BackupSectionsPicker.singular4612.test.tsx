/**
 * @vitest-environment jsdom
 *
 * A section of one table reads "1 table" (#4612).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BackupSection } from "@/lib/api";

const catalog: BackupSection[] = [
  {
    key: "diagnostics",
    label: "Diagnostics",
    description: "",
    table_count: 1,
    volatile: false,
    selectable: true,
    also_restores: [],
  },
  {
    key: "ipam",
    label: "IPAM",
    description: "",
    table_count: 12,
    volatile: false,
    selectable: true,
    also_restores: [],
  },
];
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    backupApi: { listSections: () => Promise.resolve(catalog) },
  };
});
const { BackupSectionsPicker } = await import("./BackupSectionsPicker");

afterEach(cleanup);

describe("BackupSectionsPicker counts", () => {
  it("says 1 table and 12 tables", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <BackupSectionsPicker
          mode="selective"
          onModeChange={() => {}}
          selected={[]}
          onChange={() => {}}
        />
      </QueryClientProvider>,
    );
    await screen.findByText("Diagnostics");
    const text = document.body.textContent ?? "";
    expect(text).toContain("1 table");
    expect(text).not.toContain("1 tables");
    expect(text).toContain("12 tables");
  });
});

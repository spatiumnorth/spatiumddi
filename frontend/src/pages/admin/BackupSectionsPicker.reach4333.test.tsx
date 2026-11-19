/**
 * @vitest-environment jsdom
 *
 * The selective picker names what a selective restore also replaces (#4333).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BackupSection } from "@/lib/api";

const sec = (over: Partial<BackupSection>): BackupSection => ({
  key: "x",
  label: "X",
  description: "",
  table_count: 1,
  volatile: false,
  selectable: true,
  also_restores: [],
  ...over,
});
const catalog: BackupSection[] = [
  sec({
    key: "dns",
    label: "DNS",
    also_restores: [
      { key: "ipam", label: "IPAM", tables: ["ip_address", "subnet"] },
    ],
  }),
  sec({ key: "ipam", label: "IPAM" }),
];
const listSections = vi.fn(() => Promise.resolve(catalog));
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, backupApi: { listSections } };
});
const { BackupSectionsPicker } = await import("./BackupSectionsPicker");
const { reachOutsideSelection } = await import("./backupSelectiveReach");

afterEach(cleanup);

describe("reachOutsideSelection", () => {
  it("names tables of unticked sections only", () => {
    expect(reachOutsideSelection(catalog, ["dns"])[0].tables).toContain(
      "ip_address",
    );
    expect(reachOutsideSelection(catalog, ["dns", "ipam"])).toEqual([]);
  });
});

describe("BackupSectionsPicker", () => {
  it("lists IP addresses for a DNS-only selective restore", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <BackupSectionsPicker
          mode="selective"
          onModeChange={() => {}}
          selected={["dns"]}
          onChange={() => {}}
        />
      </QueryClientProvider>,
    );
    const list = await screen.findByTestId("selective-reach");
    expect(list.textContent).toContain("ip_address");
    expect(list.textContent).toContain("IPAM");
    expect(document.body.textContent).not.toContain("are also removed");
  });
});

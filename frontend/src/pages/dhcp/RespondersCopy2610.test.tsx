/**
 * @vitest-environment jsdom
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dhcpApi: { ...actual.dhcpApi, listResponders: () => Promise.resolve([]) },
  };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});

const { RespondersTab } = await import("./DHCPPage");
afterEach(cleanup);

describe("Responders tab copy (#2610)", () => {
  it("says the alert fires only once its rule is enabled", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <RespondersTab groupId="g1" />
      </QueryClientProvider>,
    );
    const said =
      (await screen.findByText(/DHCP servers seen answering/)).textContent ??
      "";
    expect(said).toMatch(/once that rule is enabled/);
    expect(said).toMatch(/ships disabled/);
  });
});

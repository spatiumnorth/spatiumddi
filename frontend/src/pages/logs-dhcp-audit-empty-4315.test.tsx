/**
 * @vitest-environment jsdom
 *
 * Logs → DHCP Audit reads only Windows DHCP servers (WinRM), so on an install
 * whose only DHCP server is Kea its empty state must not claim that no DHCP
 * server exists (#4315).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    logsApi: new Proxy(actual.logsApi, {
      get(_t, prop) {
        if (prop === "listSources") return () => Promise.resolve([]);
        if (prop === "listAgentSources")
          return () =>
            Promise.resolve([
              {
                server_id: "k1",
                server_name: "kea-1",
                server_kind: "dhcp",
                driver: "kea",
                host: "kea-1",
                group_id: null,
                group_name: null,
              },
            ]);
        return () => new Promise(() => {});
      },
    }),
  };
});

const { LogsPage } = await import("./LogsPage");

afterEach(cleanup);

describe("DHCP Audit empty state (#4315)", () => {
  it("names Windows DHCP servers, not every DHCP server", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={["/logs?tab=audit"]}>
          <LogsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(
      await screen.findByText("No Windows DHCP servers configured"),
    ).toBeTruthy();
    expect(screen.queryByText("No DHCP servers configured")).toBeNull();
  });
});

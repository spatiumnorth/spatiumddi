/**
 * @vitest-environment jsdom
 *
 * Logs → the server picked on DNS Queries / DHCP Activity survives a switch
 * to another Logs tab and back (#4234): only the active tab is mounted, so a
 * plain useState lost it. A stored pick that is no longer readable falls back
 * to the default.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const src = (id: string, kind: "dns" | "dhcp") => ({
  server_id: id,
  server_name: `${kind}-${id}`,
  server_kind: kind,
  driver: kind === "dns" ? "bind9" : "kea",
  host: `${kind}-${id}`,
  group_id: null,
  group_name: null,
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const never = () => new Promise(() => {});
  return {
    ...actual,
    logsApi: new Proxy(actual.logsApi, {
      get(_t, prop) {
        if (prop === "listSources") return () => Promise.resolve([]);
        if (prop === "listAgentSources")
          return () =>
            Promise.resolve([
              src("a1", "dns"),
              src("a2", "dns"),
              src("d1", "dhcp"),
              src("d2", "dhcp"),
            ]);
        return never;
      },
    }),
  };
});

const { LogsPage } = await import("./LogsPage");

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/logs?tab=dns-queries"]}>
        <LogsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const picker = async () =>
  (await screen.findByLabelText("Server")) as HTMLSelectElement;

beforeEach(() => sessionStorage.clear());
afterEach(cleanup);

describe("Logs server pick (#4234)", () => {
  it("keeps the DNS Queries pick across a tab switch", async () => {
    renderPage();
    expect((await picker()).value).toBe("server:a1");
    fireEvent.change(await picker(), { target: { value: "server:a2" } });
    expect((await picker()).value).toBe("server:a2");
    fireEvent.click(screen.getByRole("button", { name: /Event Log/ }));
    expect(screen.queryByLabelText("Server")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /DNS Queries/ }));
    expect((await picker()).value).toBe("server:a2");
  });

  it("keeps the DHCP Activity pick across a tab switch", async () => {
    renderPage();
    fireEvent.click(
      await screen.findByRole("button", { name: /DHCP Activity/ }),
    );
    expect((await picker()).value).toBe("server:d1");
    fireEvent.change(await picker(), { target: { value: "server:d2" } });
    fireEvent.click(screen.getByRole("button", { name: /Event Log/ }));
    fireEvent.click(screen.getByRole("button", { name: /DHCP Activity/ }));
    expect((await picker()).value).toBe("server:d2");
  });

  it("falls back to the default when the stored server is gone", async () => {
    sessionStorage.setItem(
      "logs-dns-queries-server",
      JSON.stringify("server:gone"),
    );
    renderPage();
    expect((await picker()).value).toBe("server:a1");
  });
});

/**
 * @vitest-environment jsdom
 *
 * #2426 — the Sync with servers result modal opens before the request returns;
 * while it is in flight it says what it is doing instead of drawing nothing.
 */
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { DNSServerGroup } from "@/lib/api";
import { SyncWithServersResultModal } from "./DNSPage";

afterEach(cleanup);

const group = { id: "g1", name: "win-group" } as unknown as DNSServerGroup;

function show(props: {
  error?: string | null;
  syncing?: boolean;
  serverCount?: number;
}) {
  const qc = new QueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SyncWithServersResultModal
          group={group}
          result={null}
          error={props.error ?? null}
          syncing={props.syncing}
          serverCount={props.serverCount}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Sync with servers modal in flight", () => {
  it("shows a spinner line naming the server count while syncing", () => {
    show({ syncing: true, serverCount: 2 });
    const status = screen.getByRole("status");
    expect(status.textContent).toMatch(/Syncing with 2 servers/);
    expect(status.textContent).toMatch(/Windows server can take a minute/);
    expect(status.textContent).toMatch(/keeps running/);
  });

  it("uses the singular for one server", () => {
    show({ syncing: true, serverCount: 1 });
    expect(screen.getByRole("status").textContent).toMatch(
      /Syncing with 1 server…/,
    );
  });

  it("shows the error and no spinner once it failed", () => {
    show({ syncing: false, error: "boom" });
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByText("boom")).toBeTruthy();
  });
});

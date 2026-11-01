/**
 * @vitest-environment jsdom
 *
 * A user without read on 'use_network_tools' is told so on opening, and no
 * Run is enabled for a request the API refuses (#3254).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const perm = { allowed: false };

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => perm.allowed,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    applianceApprovalApi: {
      ...actual.applianceApprovalApi,
      list: vi.fn().mockResolvedValue([]),
    },
  };
});

const { NetworkToolsPage } = await import("./NetworkToolsPage");

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NetworkToolsPage />
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("Network Tools without read on use_network_tools", () => {
  it("disables Run and says why before any click", () => {
    perm.allowed = false;
    show();
    const run = screen.getByRole("button", { name: /^Run/ });
    expect((run as HTMLButtonElement).disabled).toBe(true);
    expect(run.getAttribute("title")).toMatch(/use_network_tools/);
    expect(screen.getByRole("alert").textContent).toMatch(
      /don't have permission to run the network tools/,
    );
  });

  it("leaves Run enabled and shows no notice for a user who may", () => {
    perm.allowed = true;
    show();
    const run = screen.getByRole("button", { name: /^Run/ });
    expect((run as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

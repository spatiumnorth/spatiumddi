/**
 * @vitest-environment jsdom
 *
 * #1261 — the Database replication card: states the trade-off, refuses to
 * offer the setting on a one-member cluster, and PUTs the chosen values.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const getPostgresSynchronous = vi.fn();
const setPostgresSynchronous = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    applianceApprovalApi: {
      ...actual.applianceApprovalApi,
      getPostgresSynchronous,
      setPostgresSynchronous,
    },
  };
});
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ isSuperadmin: true, isLoading: false }),
}));

const { DatabaseReplicationCard } =
  await import("@/pages/appliance/DatabaseReplicationCard");

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <DatabaseReplicationCard />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  getPostgresSynchronous.mockReset();
  setPostgresSynchronous.mockReset();
});
afterEach(cleanup);

describe("#1261 database replication card", () => {
  it("cannot be enabled on a single-member cluster", async () => {
    getPostgresSynchronous.mockResolvedValue({
      enabled: false,
      method: "any",
      number: 1,
      data_durability: "required",
      instances: 1,
    });
    mount();
    expect(await screen.findByText(/Needs at least 2/)).toBeTruthy();
    const box = screen.getByRole("checkbox") as HTMLInputElement;
    expect(box.disabled).toBe(true);
  });

  it("states the trade-off and saves the chosen values", async () => {
    getPostgresSynchronous.mockResolvedValue({
      enabled: false,
      method: "any",
      number: 1,
      data_durability: "required",
      instances: 3,
    });
    setPostgresSynchronous.mockImplementation((b) =>
      Promise.resolve({ ...b, instances: 3 }),
    );
    mount();
    fireEvent.click(await screen.findByRole("checkbox"));
    expect(screen.getByText(/stops accepting writes/)).toBeTruthy();
    expect(screen.getByText(/degrades to/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Saved/);
    expect(setPostgresSynchronous).toHaveBeenCalledWith({
      enabled: true,
      method: "any",
      number: 1,
      data_durability: "required",
    });
  });
});

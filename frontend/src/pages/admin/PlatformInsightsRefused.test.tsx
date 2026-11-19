/**
 * @vitest-environment jsdom
 *
 * Platform Insights stops asking for what the server refused, and says so
 * (#2528). Every read behind the Postgres, Redis and Services tabs is
 * superadmin-only; a Viewer's page used to ask them again every 10 to 60 s
 * (each one a `denied` audit row) and show dashes with no word.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const refused = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "Superadmin required" } },
  });
const pg = {
  overview: vi.fn(),
  tables: vi.fn(),
  connections: vi.fn(),
  slowQueries: vi.fn(),
  schemaHealth: vi.fn(),
};
const redis = { overview: vi.fn(), keyspace: vi.fn(), wakeBus: vi.fn() };
const services = { list: vi.fn() };

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    postgresApi: pg,
    redisApi: redis,
    serviceControlApi: services,
  };
});

const { PlatformInsightsPage } = await import("./PlatformInsightsPage");

beforeEach(() => {
  vi.useFakeTimers();
  for (const m of [
    ...Object.values(pg),
    ...Object.values(redis),
    ...Object.values(services),
  ]) {
    m.mockReset();
    m.mockImplementation(refused);
  }
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function minute() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(61_000);
  });
}

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <PlatformInsightsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {});
}

describe("Platform Insights over refused reads", () => {
  it("asks each Postgres read once and says why the cards are empty", async () => {
    await show();
    await minute();
    for (const [name, m] of Object.entries(pg)) {
      expect(m, name).toHaveBeenCalledTimes(1);
    }
    expect(screen.getByRole("alert").textContent).toContain(
      "You don't have permission to see Postgres statistics",
    );
  });

  it("does the same on the Redis tab", async () => {
    await show();
    fireEvent.click(screen.getByRole("button", { name: /^Redis/ }));
    await minute();
    for (const [name, m] of Object.entries(redis)) {
      expect(m, name).toHaveBeenCalledTimes(1);
    }
    expect(screen.getByRole("alert").textContent).toContain(
      "You don't have permission to see Redis statistics",
    );
  });

  it("stops polling the Services inventory once refused", async () => {
    await show();
    fireEvent.click(screen.getByRole("button", { name: /^Services/ }));
    await minute();
    expect(services.list).toHaveBeenCalledTimes(1);
  });

  it("keeps polling a read that merely failed", async () => {
    pg.overview.mockImplementation(() =>
      Promise.reject({ response: { status: 500, data: { detail: "boom" } } }),
    );
    await show();
    await minute();
    expect(pg.overview.mock.calls.length).toBeGreaterThan(1);
  });
});

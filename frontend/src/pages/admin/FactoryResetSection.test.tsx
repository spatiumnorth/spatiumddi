/**
 * @vitest-environment jsdom
 *
 * The Factory Reset tab says a refused section-catalog read was refused,
 * not only that it failed (#2948).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const listSections = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, factoryResetApi: { listSections } };
});

const { FactoryResetSection } = await import("./FactoryResetSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function renderIt() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <FactoryResetSection />
    </QueryClientProvider>,
  );
}

describe("FactoryResetSection catalog read errors (#2948)", () => {
  it("says a 403 was a refusal, with the reason", async () => {
    listSections.mockRejectedValue(
      Object.assign(new Error("Request failed with status code 403"), {
        response: { status: 403, data: { detail: "Superadmin required" } },
      }),
    );
    renderIt();
    await screen.findByText(/permission to see .*section catalog/i);
    expect(screen.getByText(/Superadmin required/)).toBeTruthy();
    expect(screen.queryByText(/Failed to load section catalog/)).toBeNull();
  });

  it("still reports another failure as a failure", async () => {
    listSections.mockRejectedValue(new Error("boom"));
    renderIt();
    await screen.findByText(/Couldn.t load the factory reset section catalog/);
  });
});

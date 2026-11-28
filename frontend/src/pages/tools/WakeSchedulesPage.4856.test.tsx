/**
 * @vitest-environment jsdom
 *
 * Calendars tab: a refused read says so, not "No calendars subscribed yet."
 * (#4856).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const refused = { response: { status: 403, data: { detail: "Forbidden" } } };

vi.mock("@/lib/api", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...real,
    wakeSchedulesApi: {
      ...real.wakeSchedulesApi,
      list: () => Promise.resolve([]),
      listCalendars: () => Promise.reject(refused),
    },
  };
});

import { WakeSchedulesPage } from "./WakeSchedulesPage";

afterEach(cleanup);

describe("Calendars tab, refused read", () => {
  it("tells the reader they may not see calendars", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <WakeSchedulesPage />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByText("Calendars"));
    const msg = await screen.findByText(/You don't have permission to see/);
    expect(msg.textContent).toContain("calendars");
    expect(document.body.textContent).not.toContain(
      "No calendars subscribed yet.",
    );
  });
});

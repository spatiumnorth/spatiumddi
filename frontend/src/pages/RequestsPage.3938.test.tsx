/**
 * @vitest-environment jsdom
 *
 * The New request pickers say when more match than they show (#3938).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    requestsApi: {
      ...actual.requestsApi,
      resourceOptions: async () => ({
        options: [{ id: "s1", label: "10.0.0.0/24", sublabel: null }],
        truncated: true,
      }),
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import { ResourcePicker } from "./RequestsPage";

afterEach(() => {
  cleanup();
});

describe("the picker says when more match than it shows (#3938)", () => {
  it("names the count shown", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ResourcePicker resource="subnet" value="" onChange={() => {}} />
      </QueryClientProvider>,
    );
    fireEvent.focus(screen.getByPlaceholderText("Type to search…"));
    expect(await screen.findByText(/Showing 1 — more match/)).toBeTruthy();
  });
});

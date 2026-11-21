/**
 * @vitest-environment jsdom
 *
 * The DNS query details' "dig this name" / "whois this domain" open the Tools
 * page with the form filled in and nothing run (#4250).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const dig = vi.fn();
const whois = vi.fn();

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    networkToolsApi: {
      ...actual.networkToolsApi,
      dig: (...a: unknown[]) => dig(...a),
      whois: (...a: unknown[]) => whois(...a),
    },
    applianceApprovalApi: {
      ...actual.applianceApprovalApi,
      list: vi.fn().mockResolvedValue([]),
    },
  };
});

const { NetworkToolsPage } = await import("./NetworkToolsPage");

function at(url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <NetworkToolsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Network Tools prefill (#4250)", () => {
  it("opens dig with the name, type and server, and does not run it", () => {
    at(
      "/tools/network?tool=dig&name=ads.example.com&type=AAAA&server=10.0.0.53",
    );
    expect(
      (screen.getByPlaceholderText("example.com") as HTMLInputElement).value,
    ).toBe("ads.example.com");
    expect((screen.getByDisplayValue("AAAA") as HTMLSelectElement).value).toBe(
      "AAAA",
    );
    expect(screen.getByDisplayValue("10.0.0.53")).toBeTruthy();
    expect(dig).not.toHaveBeenCalled();
  });

  it("opens whois with the query, and not run", () => {
    at("/tools/network?tool=whois&query=example.com");
    expect(screen.getByDisplayValue("example.com")).toBeTruthy();
    expect(whois).not.toHaveBeenCalled();
  });

  it("falls back to ping for an unknown tool, and drops the prefill on a tool switch", () => {
    at("/tools/network?tool=nope&name=ads.example.com");
    expect(screen.queryByDisplayValue("ads.example.com")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /^dig/i }));
    expect(
      (screen.getByPlaceholderText("example.com") as HTMLInputElement).value,
    ).toBe("");
  });
});

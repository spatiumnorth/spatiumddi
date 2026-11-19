/**
 * @vitest-environment jsdom
 *
 * The "module is off" notice names Features & Integrations and links it, for
 * a superadmin only (#2129).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const me = { is_superadmin: true };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const off = () => Promise.reject({ response: { status: 404 } });
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => me },
    dnsThreatApi: new Proxy({}, { get: () => off }),
  };
});

import { DNSThreatTab } from "./DNSThreatTab";

function renderTab() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <DNSThreatTab />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("DNS Threat module-off notice (#2129)", () => {
  it("links Features & Integrations for a superadmin", async () => {
    me.is_superadmin = true;
    renderTab();
    const link = await screen.findByRole("link", {
      name: "Features & Integrations",
    });
    expect(link.getAttribute("href")).toBe("/admin/features");
    expect(document.body.textContent).not.toContain("in Settings");
  });

  it("tells everyone else to ask an administrator, with no link", async () => {
    me.is_superadmin = false;
    renderTab();
    await screen.findByText("DNS threat analytics is off");
    expect(screen.queryByRole("link")).toBeNull();
    expect(document.body.textContent).toContain("Ask an administrator");
  });
});

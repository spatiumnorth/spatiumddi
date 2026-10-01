/**
 * @vitest-environment jsdom
 *
 * Not-found page (#1360).
 *
 * Two things are worth pinning. The requested path is attacker-chosen —
 * anyone can send an operator a link — so it must render as text, never
 * as markup. And the quick links must be gated by the same module
 * predicate the sidebar uses, or the page suggests a destination the
 * sidebar is hiding, whose page then 404s at the API.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let disabled = new Set<string>();
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: (id: string) => !disabled.has(id) }),
}));

const { NotFoundPage } = await import("./NotFoundPage");

afterEach(() => {
  cleanup();
  disabled = new Set();
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <NotFoundPage />
    </MemoryRouter>,
  );
}

describe("NotFoundPage", () => {
  it("echoes the requested path as text, never as markup", () => {
    const { container } = renderAt("/ipam/<script>alert(1)</script>");
    expect(screen.getByTestId("not-found-path").textContent).toBe(
      "/ipam/<script>alert(1)</script>",
    );
    expect(container.querySelector("script")).toBeNull();
  });

  it("elides a very long path instead of printing all of it", () => {
    const long = "/" + "a".repeat(500);
    renderAt(long);
    const shown = screen.getByTestId("not-found-path").textContent ?? "";
    expect(shown.length).toBeLessThan(200);
    expect(shown).toContain("…");
  });

  it("keeps a malformed percent-encoding as requested", () => {
    renderAt("/ipam/%E0%A4%A");
    expect(screen.getByTestId("not-found-path").textContent).toBe(
      "/ipam/%E0%A4%A",
    );
  });

  it("offers the dashboard and the feature-module hint", () => {
    renderAt("/nope");
    expect(
      screen.getByRole("link", { name: /back to dashboard/i }),
    ).toHaveProperty("pathname", "/dashboard");
    expect(
      screen.getByRole("link", { name: /settings → features/i }),
    ).toHaveProperty("pathname", "/admin/features");
  });

  it("suggests pages under the same first segment first", () => {
    renderAt("/dns/zonez");
    const hrefs = screen
      .getAllByRole("listitem")
      .map((li) => li.querySelector("a")?.getAttribute("href"));
    expect(hrefs[0]).toBe("/dns");
    expect(hrefs).toContain("/dns/pools");
  });

  it("never suggests a page whose module is off", () => {
    disabled = new Set(["core.dns"]);
    renderAt("/dns/zonez");
    const hrefs = screen
      .getAllByRole("listitem")
      .map((li) => li.querySelector("a")?.getAttribute("href"));
    expect(hrefs).not.toContain("/dns");
    // Still useful: falls back to the default destinations.
    expect(hrefs).toContain("/ipam");
  });
});

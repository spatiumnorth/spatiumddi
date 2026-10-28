/**
 * @vitest-environment jsdom
 *
 * About page (#2895) — it has to work logged out, carry the licence and the
 * full NOTICE, and link the generated third-party lists.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => ({ isAuthenticated: false, bootstrapping: false }),
}));

const versionGet = vi.fn();
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<object>("@/lib/api")),
  versionApi: { get: () => versionGet() },
}));

import {
  AboutPage,
  NPM_LICENSES_PATH,
  PYTHON_LICENSES_PATH,
} from "@/pages/AboutPage";

const NOTICE = "SpatiumDDI\nCopyright 2024 SpatiumDDI Contributors\n";

function textResponse(body: string, type = "text/plain") {
  return new Response(body, { status: 200, headers: { "content-type": type } });
}

function renderAbout() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AboutPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.stubGlobal("__APP_VERSION__", "dev");
  versionGet.mockResolvedValue({
    version: "2026.10.27-1",
    appliance_mode: true,
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  versionGet.mockReset();
});

describe("AboutPage (#2895)", () => {
  it("renders logged out with the licence, version, company and NOTICE", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => textResponse(NOTICE)),
    );
    renderAbout();

    expect(screen.getByText("About SpatiumDDI")).toBeTruthy();
    expect(screen.getByText(/Apache License, Version 2\.0/)).toBeTruthy();
    expect(screen.getAllByText(/Spatium North/).length).toBeGreaterThan(0);
    // Logged out: the way back is the sign-in page.
    expect(screen.getByText("Back to sign in")).toBeTruthy();
    await waitFor(() =>
      expect(screen.getByTestId("about-notice").textContent).toBe(NOTICE),
    );
    await waitFor(() =>
      expect(screen.getByTestId("about-version").textContent).toContain(
        "2026.10.27-1",
      ),
    );
  });

  it("links the source, docs, privacy and both generated lists", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => textResponse(NOTICE)),
    );
    renderAbout();
    await screen.findByTestId("about-notice");

    const hrefs = screen
      .getAllByRole("link")
      .map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("https://github.com/spatiumnorth/spatiumddi");
    expect(hrefs).toContain("https://www.spatiumddi.com");
    expect(hrefs).toContain("https://www.spatiumddi.com/PRIVACY.html");
    expect(hrefs).toContain(NPM_LICENSES_PATH);
    expect(hrefs).toContain(PYTHON_LICENSES_PATH);
    expect(hrefs).toContain("/legal/LICENSE.txt");
  });

  it("treats an HTML fallback as an absent NOTICE, not as licence text", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        textResponse("<!doctype html><html></html>", "text/html"),
      ),
    );
    renderAbout();

    await waitFor(() =>
      expect(screen.getByTestId("about-notice-absent")).toBeTruthy(),
    );
    expect(screen.queryByTestId("about-notice")).toBeNull();
  });

  it("says GPL components belong to the appliance image when not on one", async () => {
    versionGet.mockResolvedValue({ version: "1.0.0", appliance_mode: false });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => textResponse(NOTICE)),
    );
    renderAbout();

    await waitFor(() =>
      expect(screen.getByTestId("about-gpl").textContent).toMatch(
        /OS appliance image includes GPL/,
      ),
    );
  });
});

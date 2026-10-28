/**
 * @vitest-environment jsdom
 *
 * About page (#2895) — the licence, the full NOTICE and the generated
 * third-party lists, for signed-in users only. Every file goes through the
 * authenticated `api` client: the session is a Bearer token in memory, and a
 * plain link or `fetch` would arrive at the server without it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const versionGet = vi.fn();
const apiGet = vi.fn();
vi.mock("@/lib/api", () => ({
  api: { get: (...args: unknown[]) => apiGet(...args) },
  versionApi: { get: () => versionGet() },
}));

import {
  AboutPage,
  LICENSE_PATH,
  NOTICE_PATH,
  NPM_LICENSES_PATH,
  PYTHON_LICENSES_PATH,
} from "@/pages/AboutPage";

const NOTICE = "SpatiumDDI\nCopyright 2024 SpatiumDDI Contributors\n";
const NPM = "react\nMIT\n";

function textResponse(data: string, type = "text/plain; charset=utf-8") {
  return { data, headers: { "content-type": type } };
}

function serve(files: Record<string, string>) {
  apiGet.mockImplementation(async (path: string) => {
    if (path in files) return textResponse(files[path]);
    throw Object.assign(new Error("Request failed with status code 404"), {
      response: { status: 404 },
    });
  });
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
  apiGet.mockReset();
});

describe("AboutPage (#2895)", () => {
  it("shows the licence, version, company and NOTICE", async () => {
    serve({ [NOTICE_PATH]: NOTICE });
    renderAbout();

    expect(screen.getByText("About SpatiumDDI")).toBeTruthy();
    expect(screen.getByText(/Apache License, Version 2\.0/)).toBeTruthy();
    expect(screen.getAllByText(/Spatium North/).length).toBeGreaterThan(0);
    await waitFor(() =>
      expect(screen.getByTestId("about-notice").textContent).toBe(NOTICE),
    );
    await waitFor(() =>
      expect(screen.getByTestId("about-version").textContent).toContain(
        "2026.10.27-1",
      ),
    );
  });

  it("fetches through the authenticated client, at the absolute path", async () => {
    serve({ [NOTICE_PATH]: NOTICE });
    renderAbout();
    await screen.findByTestId("about-notice");

    const [path, config] = apiGet.mock.calls[0];
    expect(path).toBe(NOTICE_PATH);
    // The client's default /api/v1 base would otherwise be prefixed.
    expect(config.baseURL).toBe("/");
  });

  it("never links the files directly, since a link carries no session", async () => {
    serve({ [NOTICE_PATH]: NOTICE });
    renderAbout();
    await screen.findByTestId("about-notice");

    const hrefs = screen
      .getAllByRole("link")
      .map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("https://github.com/spatiumnorth/spatiumddi");
    expect(hrefs).toContain("https://www.spatiumddi.com");
    expect(hrefs).toContain("https://www.spatiumddi.com/PRIVACY.html");
    for (const path of [
      LICENSE_PATH,
      NOTICE_PATH,
      NPM_LICENSES_PATH,
      PYTHON_LICENSES_PATH,
    ]) {
      expect(hrefs).not.toContain(path);
    }
  });

  it("loads the long lists only when asked", async () => {
    serve({ [NOTICE_PATH]: NOTICE, [NPM_LICENSES_PATH]: NPM });
    renderAbout();
    await screen.findByTestId("about-notice");
    expect(apiGet.mock.calls.map((c) => c[0])).not.toContain(NPM_LICENSES_PATH);

    fireEvent.click(screen.getByText(/Show the Web UI libraries/));

    await waitFor(() =>
      expect(screen.getByTestId("about-npm").textContent).toBe(NPM),
    );
  });

  it("says a list is absent rather than showing an empty one", async () => {
    serve({ [NOTICE_PATH]: NOTICE });
    renderAbout();
    await screen.findByTestId("about-notice");

    fireEvent.click(screen.getByText(/Show the backend libraries/));

    await waitFor(() =>
      expect(screen.getByTestId("about-python-absent")).toBeTruthy(),
    );
    expect(apiGet.mock.calls.map((c) => c[0])).toContain(PYTHON_LICENSES_PATH);
  });

  it("treats an HTML fallback as an absent NOTICE, not as licence text", async () => {
    apiGet.mockResolvedValue(
      textResponse("<!doctype html><html></html>", "text/html"),
    );
    renderAbout();

    await waitFor(() =>
      expect(screen.getByTestId("about-notice-absent")).toBeTruthy(),
    );
    expect(screen.queryByTestId("about-notice")).toBeNull();
  });

  it("says GPL components belong to the appliance image when not on one", async () => {
    versionGet.mockResolvedValue({ version: "1.0.0", appliance_mode: false });
    serve({ [NOTICE_PATH]: NOTICE });
    renderAbout();

    await waitFor(() =>
      expect(screen.getByTestId("about-gpl").textContent).toMatch(
        /OS appliance image includes GPL/,
      ),
    );
  });
});

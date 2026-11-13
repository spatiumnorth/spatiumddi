/**
 * @vitest-environment jsdom
 *
 * Containers tab states (#3761): Docker only, Kubernetes only, both, neither.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const containers = {
  stats: vi.fn(),
  backends: vi.fn(),
  pods: vi.fn(),
  podLogs: vi.fn(),
};
const streamPodLogs = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    containersApi: containers,
    streamPodLogs: (...a: unknown[]) => streamPodLogs(...a),
    versionApi: { get: () => Promise.resolve({ appliance_mode: false }) },
  };
});

const { PlatformInsightsPage } = await import("./PlatformInsightsPage");

const ok = { available: true, reason: null, detail: null };
const no = (reason: string) => ({ available: false, reason, detail: null });
const pod = {
  name: "rel-api-1",
  component: "api",
  image: "x",
  state: "running",
  status: "Running (healthy)",
  health: "healthy",
  started_at: null,
  containers: ["api"],
};

async function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/admin/platform-insights#containers"]}>
        <PlatformInsightsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByRole("button", { name: /Containers/ }));
}

beforeEach(() => {
  containers.stats.mockResolvedValue({ available: true, rows: [] });
  containers.pods.mockResolvedValue({
    available: true,
    reason: null,
    rows: [pod],
  });
  streamPodLogs.mockImplementation(async function* () {
    yield "hello line";
  });
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Containers tab backends", () => {
  it("kubernetes only: pods + log viewer, docker notice", async () => {
    containers.backends.mockResolvedValue({
      docker: no("/var/run/docker.sock is not mounted"),
      kubernetes: { ...ok, detail: "spatium" },
      appliance: false,
    });
    await open();
    expect(await screen.findByText("rel-api-1")).toBeTruthy();
    expect(screen.getByTestId("backend-unavailable-docker")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "View logs" }));
    expect(await screen.findByText(/hello line/)).toBeTruthy();
  });

  it("neither: names both, with the toggle", async () => {
    containers.backends.mockResolvedValue({
      docker: no("docker.sock missing"),
      kubernetes: no("Set api.serviceAccount.enabled=true"),
      appliance: false,
    });
    await open();
    expect(
      await screen.findByText(/api\.serviceAccount\.enabled/),
    ).toBeTruthy();
    expect(screen.getByTestId("backend-unavailable-docker")).toBeTruthy();
    expect(containers.pods).not.toHaveBeenCalled();
  });

  it("both: pods and the docker table", async () => {
    containers.backends.mockResolvedValue({
      docker: ok,
      kubernetes: { ...ok, detail: "spatium" },
      appliance: false,
    });
    await open();
    expect(await screen.findByText("rel-api-1")).toBeTruthy();
    expect(await screen.findByText("No containers match.")).toBeTruthy();
  });

  it("docker only: no kubernetes section", async () => {
    containers.backends.mockResolvedValue({
      docker: ok,
      kubernetes: no("Set api.serviceAccount.enabled=true"),
      appliance: false,
    });
    await open();
    expect(await screen.findByText("No containers match.")).toBeTruthy();
    expect(screen.queryByTestId("kube-pods")).toBeNull();
  });
});

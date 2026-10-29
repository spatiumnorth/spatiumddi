/**
 * @vitest-environment jsdom
 *
 * #2618 — the Maintenance tab said both that future tasks will read the flag
 * and that scheduled tasks refuse work on it now. Nothing reads it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", () => ({
  applianceSystemApi: {
    info: vi.fn().mockResolvedValue({ maintenance_mode: false }),
    setMaintenance: vi.fn(),
    reboot: vi.fn(),
  },
  formatApiError: (e: unknown) => String(e),
}));
vi.mock("@/hooks/useApplianceAdmin", () => ({
  useApplianceAdminGate: () => ({}),
}));

import { applianceSystemApi } from "@/lib/api";
import { MaintenanceTab } from "./MaintenanceTab";

afterEach(cleanup);

describe("MaintenanceTab copy", () => {
  it("does not claim scheduled tasks act on the flag", async () => {
    const qc = new QueryClient();
    const { container } = render(
      <QueryClientProvider client={qc}>
        <MaintenanceTab />
      </QueryClientProvider>,
    );
    await screen.findByText("Maintenance mode");
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/scheduled tasks check this flag/i);
    expect(text).not.toMatch(/refuse to issue/i);
    expect(text).not.toMatch(/future tasks read it/i);
    expect(text).toMatch(/nothing drains DNS\/DHCP traffic from it yet/i);
    expect(text).toMatch(/No scheduled task, agent or service reads the flag/i);
  });
});

describe("MaintenanceTab reboot button (#3008)", () => {
  async function renderWith(info: Record<string, unknown>) {
    vi.mocked(applianceSystemApi.info).mockResolvedValue(info as never);
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MaintenanceTab />
      </QueryClientProvider>,
    );
    await screen.findByText("Maintenance mode");
  }

  it("stays disabled while the host's reboot is under way, trigger renamed", async () => {
    await renderWith({
      reboot_scheduled: false,
      reboot_in_progress: true,
    });
    const btn = await screen.findByRole("button", {
      name: /already scheduled/i,
    });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
  });

  it("is enabled when nothing is under way", async () => {
    await renderWith({
      reboot_scheduled: false,
      reboot_in_progress: false,
    });
    const btn = await screen.findByRole("button", { name: /reboot now/i });
    expect((btn as HTMLButtonElement).disabled).toBe(false);
  });

  it("names the node the banner is about", async () => {
    await renderWith({
      reboot_scheduled: false,
      reboot_in_progress: true,
      node: "ddi2",
    });
    expect(await screen.findByText(/Reboot in flight on ddi2\./)).toBeTruthy();
  });
});

describe("MaintenanceTab polling (#3008, QA case 3)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("sees a Fleet or console reboot within 5 s and then polls every 2 s", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const info = vi.mocked(applianceSystemApi.info);
    info.mockReset();
    info.mockResolvedValue({
      reboot_scheduled: false,
      reboot_in_progress: false,
    } as never);
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MaintenanceTab />
      </QueryClientProvider>,
    );
    const btn = await screen.findByRole("button", { name: /reboot now/i });
    expect((btn as HTMLButtonElement).disabled).toBe(false);
    const before = info.mock.calls.length;

    // a reboot started elsewhere; the old 15 s interval missed it entirely
    info.mockResolvedValue({
      reboot_scheduled: false,
      reboot_in_progress: true,
    } as never);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(info.mock.calls.length).toBe(before + 1);
    expect(
      (
        (await screen.findByRole("button", {
          name: /already scheduled/i,
        })) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(await screen.findByText(/Reboot in flight/)).toBeTruthy();

    const during = info.mock.calls.length;
    await vi.advanceTimersByTimeAsync(2_000);
    expect(info.mock.calls.length).toBe(during + 1);
  });
});

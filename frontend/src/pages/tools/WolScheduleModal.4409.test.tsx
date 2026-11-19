/**
 * @vitest-environment jsdom
 *
 * Editing a UTC schedule must stay saveable when the browser's
 * Intl.supportedValuesOf("timeZone") has no "UTC" (Chromium) (#4409).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { WolSchedule } from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    wakeSchedulesApi: {
      ...actual.wakeSchedulesApi,
      listCalendars: vi.fn().mockResolvedValue([]),
      previewTargets: vi.fn().mockResolvedValue({ total: 0, sample: [] }),
      update: vi.fn().mockResolvedValue({}),
    },
    ipamApi: {
      ...actual.ipamApi,
      listSubnets: vi.fn().mockResolvedValue([]),
    },
  };
});

const { WolScheduleModal } = await import("./WakeSchedulesPage");

const schedule: WolSchedule = {
  id: "11111111-1111-1111-1111-111111111111",
  name: "Morning boot",
  description: null,
  enabled: true,
  target_selector: {
    mode: "address_tags",
    tags: ["lab"],
    subnet_ids: [],
    address_ids: [],
  },
  schedule_cron: "0 7 * * 1-5",
  timezone: "UTC",
  blackout_dates: null,
  active_from: null,
  active_until: null,
  calendar_id: null,
  calendar_mode: "none",
  calendar_match: null,
  vantage: { kind: "server", id: null },
  repeat_count: 2,
  repeat_interval_ms: 150,
  stagger_ms: 40,
  port: 9,
  verify_enabled: false,
  verify_wait_seconds: 60,
  verify_retries: 1,
  verify_alert_enabled: true,
  verify_method: "auto",
  last_run_at: null,
  last_run_status: null,
  last_run_skip_reason: null,
  last_target_count: null,
  next_run_at: null,
  created_by_user_id: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
};

/** Chromium-like Intl: the zone list has no "UTC". */
function stubZones(list: string[]) {
  vi.stubGlobal(
    "Intl",
    Object.assign(Object.create(Intl), { supportedValuesOf: () => list }),
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function open() {
  stubZones(["Europe/Paris"]);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <WolScheduleModal
        existing={schedule}
        onClose={() => {}}
        onSaved={() => {}}
      />
    </QueryClientProvider>,
  );
  fireEvent.change(
    screen.getByPlaceholderText("Classroom PCs — morning boot"),
    {
      target: { value: "Morning boot 2" },
    },
  );
  fireEvent.click(screen.getByRole("button", { name: "Schedule" }));
}

const saveBtn = () =>
  screen.getByRole("button", { name: /^save/i }) as HTMLButtonElement;

describe("wake schedule dialog time zone (#4409)", () => {
  it("lets a UTC schedule be saved after a rename", { timeout: 30000 }, () => {
    open();
    expect(saveBtn().disabled).toBe(false);
    expect(screen.queryByText(/Not a recognised IANA/)).toBeNull();
  });

  it("still refuses a bad name", { timeout: 30000 }, () => {
    open();
    fireEvent.change(screen.getByPlaceholderText("America/New_York"), {
      target: { value: "Mars/Base" },
    });
    expect(saveBtn().disabled).toBe(true);
    expect(screen.getByText(/Not a recognised IANA/)).toBeTruthy();
  });
});

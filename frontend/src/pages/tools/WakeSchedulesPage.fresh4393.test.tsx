/**
 * @vitest-environment jsdom
 *
 * The wake schedule Edit dialog diffs a Save against the row as the form seeds
 * it (#4379). A schedule whose blackout_dates is null is seeded as [], so an
 * untouched Save used to send `blackout_dates: []`, and a Save of the name
 * alone wiped blackout dates another client set meanwhile.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const h = vi.hoisted(() => ({ update: vi.fn() }));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    wakeSchedulesApi: {
      ...actual.wakeSchedulesApi,
      update: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve({});
      },
      previewTargets: () => Promise.resolve({ total: 0, targets: [] }),
      listCalendars: () => Promise.resolve([]),
    },
  };
});

const { WolScheduleModal } = await import("./WakeSchedulesPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const ROW = {
  id: "s1",
  name: "Classroom PCs",
  description: null,
  enabled: true,
  target_selector: {
    mode: "address_tags",
    tags: ["lab"],
    subnet_ids: [],
    address_ids: [],
  },
  schedule_cron: "0 7 * * 1-5",
  timezone: "Europe/Berlin",
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

function open() {
  const onSaved = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <WolScheduleModal
        existing={ROW as never}
        onClose={() => {}}
        onSaved={onSaved}
      />
    </QueryClientProvider>,
  );
  return onSaved;
}

describe("wake schedule Edit save diff (#4379)", { timeout: 30000 }, () => {
  it("an untouched Save sends nothing", async () => {
    const onSaved = open();
    const save = await screen.findByRole("button", { name: /^save/i });
    await waitFor(
      () => expect((save as HTMLButtonElement).disabled).toBe(false),
      { timeout: 10000 },
    );
    fireEvent.click(save);
    await waitFor(() => expect(onSaved).toHaveBeenCalled(), {
      timeout: 10000,
    });
    expect(h.update).not.toHaveBeenCalled();
  });

  it("a Save of the name alone sends only the name", async () => {
    const onSaved = open();
    const input = await screen.findByDisplayValue("Classroom PCs");
    fireEvent.change(input, { target: { value: "Renamed" } });
    const save = await screen.findByRole("button", { name: /^save/i });
    await waitFor(
      () => expect((save as HTMLButtonElement).disabled).toBe(false),
      { timeout: 10000 },
    );
    fireEvent.click(save);
    await waitFor(() => expect(h.update).toHaveBeenCalled(), {
      timeout: 10000,
    });
    expect(h.update).toHaveBeenCalledWith("s1", { name: "Renamed" });
    await waitFor(() => expect(onSaved).toHaveBeenCalled(), {
      timeout: 10000,
    });
  });
});

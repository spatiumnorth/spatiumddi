/**
 * @vitest-environment jsdom
 *
 * #4830: scheduling a record change. The form checks what the server would
 * refuse and sends the local time as UTC; the zone's list shows each state and
 * offers Cancel on a pending change only.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import type { DNSScheduledChange } from "@/lib/api";
import { ScheduledChangesPanel } from "./ScheduledChanges";
import {
  buildScheduleBody,
  localToUtcIso,
  validateSchedule,
  type ScheduleForm,
} from "./scheduledChangesForm";

const list = vi.fn();
const cancel = vi.fn();
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listScheduledChanges: (...a: unknown[]) => list(...a),
      cancelScheduledChange: (...a: unknown[]) => cancel(...a),
    },
  };
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const wrap = (ui: ReactNode) => (
  <QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>
);

const base: ScheduleForm = {
  kind: "create",
  when: "2099-01-01T02:00",
  name: "www",
  recordType: "A",
  value: "192.0.2.1",
  ttl: "",
};

describe("schedule form validation", () => {
  it("refuses what the server would, in order", () => {
    expect(validateSchedule({ ...base, when: "" })).toMatch(/date and time/);
    expect(validateSchedule({ ...base, when: "2001-01-01T00:00" })).toMatch(
      /future/,
    );
    expect(validateSchedule({ ...base, ttl: "abc" })).toMatch(/TTL/);
    expect(validateSchedule({ ...base, name: " " })).toMatch(/name/);
    expect(validateSchedule({ ...base, value: "" })).toMatch(/value/);
    expect(
      validateSchedule({ ...base, kind: "update", value: "", ttl: "" }),
    ).toMatch(/value or the TTL/);
    expect(validateSchedule(base)).toBeNull();
    expect(
      validateSchedule({ ...base, kind: "delete", name: "", value: "" }),
    ).toBeNull();
  });

  it("sends the local wall-clock time as a UTC instant", () => {
    const iso = localToUtcIso("2099-01-01T02:00") as string;
    expect(iso.endsWith("Z")).toBe(true);
    expect(new Date(iso).getTime()).toBe(
      new Date("2099-01-01T02:00").getTime(),
    );
    expect(localToUtcIso("")).toBeNull();
    expect(buildScheduleBody(base, null)).toMatchObject({
      action: "create",
      scheduled_at: iso,
      record: { name: "www", record_type: "A", value: "192.0.2.1" },
    });
    const rec = { id: "r1" } as never;
    expect(buildScheduleBody({ ...base, kind: "delete" }, rec)).toEqual({
      action: "delete",
      scheduled_at: iso,
      record_id: "r1",
    });
  });
});

const change = (over: Partial<DNSScheduledChange>): DNSScheduledChange => ({
  id: "c",
  zone_id: "z",
  record_id: null,
  action: "create",
  payload: {},
  record_label: "www.example. A",
  scheduled_at: "2099-01-01T02:00:00Z",
  state: "pending",
  result_message: null,
  started_at: null,
  finished_at: null,
  created_by_user_id: null,
  created_by_display: "x",
  created_at: "2099-01-01T00:00:00Z",
  modified_at: "2099-01-01T00:00:00Z",
  ...over,
});

describe("scheduled changes list", () => {
  it("shows every state and cancels only a pending one", async () => {
    list.mockResolvedValue({
      items: [
        change({ id: "p", state: "pending", record_label: "a.example. A" }),
        change({ id: "d", state: "executed", record_label: "b.example. A" }),
        change({
          id: "f",
          state: "failed",
          record_label: "c.example. A",
          result_message: "Refused: twin",
        }),
        change({ id: "x", state: "cancelled", record_label: "d.example. A" }),
      ],
      total: 4,
      page: 1,
      page_size: 100,
    });
    cancel.mockResolvedValue({});
    render(
      wrap(
        <ScheduledChangesPanel
          groupId="g"
          zoneId="z"
          canWrite
          onSchedule={() => {}}
        />,
      ),
    );
    expect(await screen.findByText("a.example. A")).toBeTruthy();
    expect(screen.getByText("1 pending change")).toBeTruthy();
    expect(screen.getByText("Refused: twin")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Cancel" })).toHaveLength(1);

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await userEvent.click(
      await screen.findByRole("button", { name: "Cancel change" }),
    );
    await waitFor(() => expect(cancel).toHaveBeenCalledWith("g", "z", "p"));
  });

  it("hides the actions from a reader", async () => {
    list.mockResolvedValue({
      items: [change({})],
      total: 1,
      page: 1,
      page_size: 100,
    });
    render(
      wrap(
        <ScheduledChangesPanel
          groupId="g"
          zoneId="z"
          canWrite={false}
          onSchedule={() => {}}
        />,
      ),
    );
    await screen.findByText("www.example. A");
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Schedule change" }),
    ).toBeNull();
  });
});

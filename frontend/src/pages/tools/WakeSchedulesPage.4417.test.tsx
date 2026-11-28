/**
 * @vitest-environment jsdom
 *
 * New wake schedule: Create is off until a target is chosen, and the API's
 * 422 reads as a sentence, not validation JSON (#4417).
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

// The modal defaults its timezone to the browser's; a CI box on plain "UTC"
// is not in Intl's IANA list, which would hold Create off for another reason.
vi.hoisted(() => {
  process.env.TZ = "Europe/London";
});

const create = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...real,
    wakeSchedulesApi: {
      ...real.wakeSchedulesApi,
      create: (...a: unknown[]) => create(...a),
      previewTargets: () =>
        Promise.resolve({ matched_count: 0, wake_count: 0, mac_less_count: 0 }),
    },
  };
});

import { WolScheduleModal } from "./WakeSchedulesPage";

afterEach(() => {
  cleanup();
  create.mockReset();
});

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <WolScheduleModal existing={null} onClose={() => {}} onSaved={() => {}} />
    </QueryClientProvider>,
  );
  fireEvent.change(screen.getByPlaceholderText(/Classroom PCs/), {
    target: { value: "Morning wake" },
  });
  return screen.getByRole("button", {
    name: /Create schedule/,
  }) as HTMLButtonElement;
}

function pickTag() {
  const input = screen.getByPlaceholderText(/Filter by tag/);
  fireEvent.change(input, { target: { value: "classroom" } });
  fireEvent.keyDown(input, { key: "Enter" });
}

describe("WolScheduleModal target gate (#4417)", () => {
  it(
    "keeps Create disabled until a tag is chosen",
    { timeout: 30000 },
    async () => {
      const btn = mount();
      await waitFor(
        () => expect(screen.getByText(/Pick at least one tag/)).toBeTruthy(),
        { timeout: 10000 },
      );
      expect(btn.disabled).toBe(true);
      pickTag();
      await waitFor(() => expect(btn.disabled).toBe(false), {
        timeout: 10000,
      });
      expect(screen.queryByText(/Pick at least one tag/)).toBeNull();
    },
  );

  it(
    "shows a 422 as readable text, not validation JSON",
    { timeout: 30000 },
    async () => {
      create.mockRejectedValue({
        response: {
          status: 422,
          data: {
            detail: [
              {
                type: "value_error",
                loc: ["body", "target_selector"],
                msg: "Value error, target_selector.tags must be non-empty for mode 'address_tags'",
                input: {},
              },
            ],
          },
        },
      });
      const btn = mount();
      pickTag();
      await waitFor(() => expect(btn.disabled).toBe(false), {
        timeout: 10000,
      });
      fireEvent.click(btn);
      const msg = await screen.findByText(/must be non-empty/, undefined, {
        timeout: 10000,
      });
      expect(msg.textContent).not.toMatch(/Value error|\{|\[/);
    },
  );
});

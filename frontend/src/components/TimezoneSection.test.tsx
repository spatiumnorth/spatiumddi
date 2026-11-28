/**
 * @vitest-environment jsdom
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

const update = vi.fn().mockResolvedValue({});
vi.mock("@/lib/api", () => ({
  settingsApi: { update: (...a: unknown[]) => update(...a) },
  formatApiError: () => "err",
}));

import { TimezoneSection } from "./TimezoneSection";

afterEach(() => {
  vi.unstubAllGlobals();
  cleanup();
  update.mockClear();
});

function mount() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <TimezoneSection currentValue="UTC" isSuperadmin applianceMode />
    </QueryClientProvider>,
  );
}

describe("TimezoneSection (#4416)", () => {
  it(
    "saves the canonical name for a legacy alias",
    { timeout: 30000 },
    async () => {
      mount();
      fireEvent.change(screen.getByPlaceholderText("UTC"), {
        target: { value: "US/Pacific" },
      });
      fireEvent.click(screen.getByText("Save"));
      await waitFor(
        () =>
          expect(update).toHaveBeenCalledWith({
            timezone: "America/Los_Angeles",
          }),
        { timeout: 10000 },
      );
    },
  );

  it("does not suggest names the host refuses", { timeout: 30000 }, () => {
    mount();
    const opts = Array.from(
      document.querySelectorAll("#iana-timezones option"),
    ).map((o) => (o as HTMLOptionElement).value);
    expect(opts).not.toContain("Asia/Calcutta");
    expect(opts).not.toContain("US/Pacific");
  });

  describe("Chromium-style list with only legacy spellings", () => {
    const stub = () => {
      const real = Intl;
      vi.stubGlobal("Intl", {
        ...real,
        DateTimeFormat: real.DateTimeFormat,
        supportedValuesOf: () => [
          "Asia/Calcutta",
          "Europe/Kiev",
          "Europe/Berlin",
        ],
      });
    };

    it("suggests the canonical names", () => {
      stub();
      mount();
      const opts = Array.from(
        document.querySelectorAll("#iana-timezones option"),
      ).map((o) => (o as HTMLOptionElement).value);
      expect(opts).toContain("Asia/Kolkata");
      expect(opts).toContain("Europe/Kyiv");
      expect(opts).toContain("Europe/Berlin");
      expect(opts).not.toContain("Asia/Calcutta");
      expect(opts).not.toContain("Europe/Kiev");
    });

    it.each([
      ["Asia/Kolkata", "Asia/Kolkata"],
      ["Asia/Calcutta", "Asia/Kolkata"],
      ["Europe/Kyiv", "Europe/Kyiv"],
    ])("saves %s as %s", async (typed, saved) => {
      stub();
      mount();
      fireEvent.change(screen.getByPlaceholderText("UTC"), {
        target: { value: typed },
      });
      fireEvent.click(screen.getByText("Save"));
      await waitFor(() =>
        expect(update).toHaveBeenCalledWith({ timezone: saved }),
      );
    });

    it("still refuses a bogus name", () => {
      stub();
      mount();
      fireEvent.change(screen.getByPlaceholderText("UTC"), {
        target: { value: "Mars/Olympus" },
      });
      fireEvent.click(screen.getByText("Save"));
      expect(update).not.toHaveBeenCalled();
    });
  });
});

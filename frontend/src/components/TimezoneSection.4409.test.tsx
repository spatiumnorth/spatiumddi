/**
 * @vitest-environment jsdom
 *
 * Chromium's Intl.supportedValuesOf("timeZone") has no "UTC"; the field must
 * still accept it, and still refuse garbage (#4409).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TimezoneSection } from "./TimezoneSection";

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

function show() {
  stubZones(["Europe/Paris", "America/Toronto"]);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <TimezoneSection currentValue="Europe/Paris" isSuperadmin applianceMode />
    </QueryClientProvider>,
  );
}

describe("TimezoneSection zone validation (#4409)", () => {
  it("enables Save for UTC", { timeout: 30000 }, () => {
    show();
    fireEvent.change(screen.getByPlaceholderText("UTC"), {
      target: { value: "UTC" },
    });
    expect(
      (screen.getByRole("button", { name: "Save" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it("refuses a bad name", { timeout: 30000 }, () => {
    show();
    fireEvent.change(screen.getByPlaceholderText("UTC"), {
      target: { value: "Mars/Base" },
    });
    expect(
      (screen.getByRole("button", { name: "Save" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(screen.getByText(/Not a recognised IANA timezone/)).toBeTruthy();
  });
});

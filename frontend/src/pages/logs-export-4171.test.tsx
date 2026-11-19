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
import { LogExportButtons } from "./LogsPage";

afterEach(cleanup);

describe("LogExportButtons (#4171)", () => {
  it("asks for the chosen format and reports a capped export", async () => {
    const onExport = vi.fn().mockResolvedValue({
      filename: "x.csv",
      rows: 3,
      capped: true,
      rowCap: 100000,
    });
    render(<LogExportButtons onExport={onExport} />);
    fireEvent.click(screen.getByRole("button", { name: "Export JSON Lines" }));
    await waitFor(() => expect(onExport).toHaveBeenCalledWith("jsonl"));
    expect((await screen.findByRole("status")).textContent).toMatch(
      /capped at 100,000 rows/,
    );
    fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
    await waitFor(() => expect(onExport).toHaveBeenLastCalledWith("csv"));
  });

  it("is disabled when there is nothing selected", () => {
    render(<LogExportButtons onExport={vi.fn()} disabled />);
    expect(
      (screen.getByRole("button", { name: "Export CSV" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });
});

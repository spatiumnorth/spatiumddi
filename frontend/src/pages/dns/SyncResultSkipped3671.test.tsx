/**
 * @vitest-environment jsdom
 *
 * The push section's "Skipped, DB already matches server" shows the answered
 * count, not a fixed 0 (#3671).
 */
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { SyncResultModal } from "./DNSPage";

afterEach(cleanup);

function show(skipped: number | undefined) {
  render(
    <SyncResultModal
      zoneName="example.com."
      drivers={["bind9"]}
      onClose={() => {}}
      result={{
        ok: true,
        server_records: 2,
        existing_in_db: 2,
        imported: 0,
        skipped_unsupported: 0,
        imported_records: [],
        push_candidates: 0,
        push_skipped_matching: skipped,
        pushed: 0,
        pushed_records: [],
        push_errors: [],
      }}
    />,
  );
}

describe("Sync with server push figures", () => {
  it("shows the answered count of records that already matched", () => {
    show(2);
    const hint = screen.getByText("DB already matches server");
    const stat = hint.parentElement as HTMLElement;
    expect(within(stat).getByText("2")).toBeTruthy();
  });

  it("falls back to 0 when the answer has no such field", () => {
    show(undefined);
    const stat = screen.getByText("DB already matches server")
      .parentElement as HTMLElement;
    expect(within(stat).getByText("0")).toBeTruthy();
  });
});

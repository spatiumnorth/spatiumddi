import { describe, expect, it } from "vitest";
import { feedChip } from "@/lib/blocklist-feed";

const NOW = Date.parse("2026-10-23T12:00:00Z");

describe("feedChip", () => {
  it("is red on error and shows the age of the last success", () => {
    const c = feedChip(
      {
        feed_sync_state: "error",
        last_success_at: "2026-10-23T08:00:00Z",
        last_sync_error: "Fetch failed: 404",
      },
      NOW,
    );
    expect(c?.tone).toBe("red");
    expect(c?.label).toContain("4h");
    expect(c?.title).toBe("Fetch failed: 404");
  });
  it("is amber with a relative age when stale", () => {
    const c = feedChip(
      { feed_sync_state: "stale", last_success_at: "2026-10-20T12:00:00Z" },
      NOW,
    );
    expect(c).toMatchObject({ tone: "amber", label: "stale · 3d ago" });
  });
  it("is grey when never synced", () => {
    expect(feedChip({ feed_sync_state: "never" }, NOW)?.tone).toBe("grey");
  });
  it("shows no staleness chip for a list the server reports as ok", () => {
    // A manual-only or disabled feed list arrives as "ok" (never/stale are
    // schedule promises); only a failed last attempt still draws a chip.
    expect(
      feedChip({ feed_sync_state: "ok", last_success_at: null }, NOW),
    ).toBeNull();
    expect(feedChip({ feed_sync_state: "error" }, NOW)?.label).toBe(
      "sync failed",
    );
  });
  it("shows nothing when healthy or when the list has no feed", () => {
    expect(feedChip({ feed_sync_state: "ok" }, NOW)).toBeNull();
    expect(feedChip({ feed_sync_state: null }, NOW)).toBeNull();
    expect(feedChip({}, NOW)).toBeNull();
  });
});

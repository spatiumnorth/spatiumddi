import { describe, expect, it } from "vitest";
import { memberCheckCell } from "@/lib/pool-health";

const NOW = Date.parse("2026-10-23T12:00:00Z");

describe("memberCheckCell", () => {
  it("shows a relative age and says it is still served when stale and healthy", () => {
    const c = memberCheckCell(
      {
        last_check_state: "healthy",
        last_check_at: "2026-10-23T08:00:00Z",
        check_stale: true,
      },
      NOW,
    );
    expect(c.stale).toBe(true);
    expect(c.text).toBe("stale \u00b7 4h ago");
    expect(c.title).toContain("still being served");
  });
  it("words the age as s/m under an hour, then h, then d", () => {
    const at = (iso: string) =>
      memberCheckCell(
        { last_check_state: "healthy", last_check_at: iso, check_stale: true },
        NOW,
      ).text;
    expect(at("2026-10-23T11:59:15Z")).toBe("stale \u00b7 45s ago");
    expect(at("2026-10-23T11:50:00Z")).toBe("stale \u00b7 10m ago");
    expect(at("2026-10-23T10:59:00Z")).toBe("stale \u00b7 1h ago");
    expect(at("2026-10-21T11:00:00Z")).toBe("stale \u00b7 2d ago");
  });
  it("does not claim the member is served when it was unhealthy", () => {
    const c = memberCheckCell(
      {
        last_check_state: "unhealthy",
        last_check_at: "2026-10-23T08:00:00Z",
        check_stale: true,
      },
      NOW,
    );
    expect(c.title).not.toContain("served");
  });
  it("is not stale when fresh, and a dash when never checked", () => {
    expect(
      memberCheckCell(
        { last_check_state: "healthy", last_check_at: "2026-10-23T11:59:00Z" },
        NOW,
      ).stale,
    ).toBe(false);
    expect(
      memberCheckCell({ last_check_state: "unknown", last_check_at: null }, NOW)
        .text,
    ).toBe("\u2014");
  });
});

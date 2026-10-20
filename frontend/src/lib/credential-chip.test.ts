import { describe, expect, it } from "vitest";

import { cardTargets, credentialChipView } from "./credential-chip";

describe("credentialChipView (#2138)", () => {
  it("is red for a rejected or expired token", () => {
    expect(credentialChipView("rejected", null, null)?.tone).toBe("red");
    expect(
      credentialChipView("expired", -2, "2026-10-01T00:00:00Z")?.label,
    ).toBe("Token expired");
  });

  it("is amber inside the window and red within a week", () => {
    expect(credentialChipView("expiring", 20, null)).toMatchObject({
      tone: "amber",
      label: "Token expires in 20 days",
    });
    expect(credentialChipView("expiring", 7, null)?.tone).toBe("red");
    expect(credentialChipView("expiring", 1, null)?.label).toBe(
      "Token expires in 1 day",
    );
    expect(credentialChipView("expiring", 0, null)?.label).toBe(
      "Token expires today",
    );
  });

  it("draws ok and unknown only when asked, and never green", () => {
    expect(credentialChipView("ok", 60, null)).toBeNull();
    expect(credentialChipView("unknown", null, null)).toBeNull();
    expect(credentialChipView("ok", 60, null, { showOk: true })?.tone).toBe(
      "muted",
    );
    expect(
      credentialChipView("unknown", null, null, { showUnknown: true })?.label,
    ).toBe("Token expiry unknown");
  });

  it("renders nothing for an integration without credential tracking", () => {
    expect(credentialChipView(null, null, null)).toBeNull();
    expect(credentialChipView(undefined, null, null)).toBeNull();
  });
});

describe("cardTargets (#2192)", () => {
  const t = (id: string, s: string | null, e: string | null = null) => ({
    id,
    credential_state: s as never,
    last_sync_error: e,
  });

  it("names every problem tenant ahead of healthy ones, past the cap", () => {
    const rows = [
      t("a", "ok"),
      t("b", "ok"),
      t("c", "ok"),
      t("d", "ok"),
      t("e", "rejected"),
      t("f", "expired"),
      t("g", "expiring"),
      t("h", "rejected"),
      t("i", "disabled"),
    ];
    const { shown, hidden } = cardTargets(rows);
    expect(shown.map((r) => r.id)).toEqual(["e", "f", "g", "h"]);
    expect(hidden).toBe(5);
  });

  it("fills up to the base with healthy rows, and counts a sync error", () => {
    const rows = [
      t("a", "ok"),
      t("b", "ok"),
      t("c", null, "boom"),
      t("d", "ok"),
    ];
    const { shown, hidden } = cardTargets(rows);
    expect(shown.map((r) => r.id)).toEqual(["c", "a", "b"]);
    expect(hidden).toBe(1);
  });

  it("draws no chip for a disabled tenant", () => {
    expect(
      credentialChipView("disabled", null, null, { showOk: true }),
    ).toBeNull();
  });
});

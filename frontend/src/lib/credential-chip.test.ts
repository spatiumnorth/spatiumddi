import { describe, expect, it } from "vitest";

import { credentialChipView } from "./credential-chip";

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

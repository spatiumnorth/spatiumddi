import { describe, expect, it } from "vitest";
import {
  upgradeAlreadyStartedRefusal,
  upgradeStartedOnHost,
} from "./upgrade-cancel";

const now = Date.parse("2026-10-17T04:00:00Z");

describe("upgradeStartedOnHost (#2021)", () => {
  it("is cancellable before the host reports anything", () => {
    expect(upgradeStartedOnHost({ last_upgrade_state: "ready" }, now)).toBe(
      false,
    );
    expect(upgradeStartedOnHost({ last_upgrade_state: null }, now)).toBe(false);
  });
  it("is not cancellable once in-flight", () => {
    expect(
      upgradeStartedOnHost(
        {
          last_upgrade_state: "in-flight",
          last_upgrade_state_at: "2026-10-17T03:59:50Z",
        },
        now,
      ),
    ).toBe(true);
  });
  it("lets a dead in-flight stamp be cancelled", () => {
    expect(
      upgradeStartedOnHost(
        {
          last_upgrade_state: "in-flight",
          last_upgrade_state_at: "2026-10-17T03:40:00Z",
        },
        now,
      ),
    ).toBe(false);
  });
  it("is not blocked for a failed or done state", () => {
    expect(upgradeStartedOnHost({ last_upgrade_state: "failed" }, now)).toBe(
      false,
    );
    expect(upgradeStartedOnHost({ last_upgrade_state: "done" }, now)).toBe(
      false,
    );
  });
});

describe("upgradeAlreadyStartedRefusal", () => {
  it("reads the 409 by code", () => {
    const err = {
      response: {
        status: 409,
        data: {
          detail: { code: "upgrade_already_started", message: "too late" },
        },
      },
    };
    expect(upgradeAlreadyStartedRefusal(err)).toBe("too late");
    expect(
      upgradeAlreadyStartedRefusal({
        response: { status: 409, data: { detail: "x" } },
      }),
    ).toBeNull();
  });
});

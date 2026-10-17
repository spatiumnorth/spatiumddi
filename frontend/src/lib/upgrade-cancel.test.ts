import { describe, expect, it } from "vitest";
import {
  hostUpgradeActivity,
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
  it("is not cancellable once the runner has claimed the trigger", () => {
    expect(
      hostUpgradeActivity(
        {
          last_upgrade_state: "in-flight",
          last_upgrade_state_at: "2026-10-17T03:59:50Z",
          last_upgrade_progress: { step: "queued" },
        },
        now,
      ),
    ).toBe("applying");
  });
  it("lets an unclaimed trigger be cancelled (the host command removes it)", () => {
    for (const step of [undefined, "", "reboot-pending", "failed"]) {
      expect(
        upgradeStartedOnHost(
          {
            last_upgrade_state: "in-flight",
            last_upgrade_state_at: "2026-10-17T03:59:50Z",
            last_upgrade_progress: step === undefined ? {} : { step },
          },
          now,
        ),
      ).toBe(false);
    }
  });
  it("lets a dead in-flight stamp be cancelled", () => {
    expect(
      upgradeStartedOnHost(
        {
          last_upgrade_state: "in-flight",
          last_upgrade_state_at: "2026-10-17T03:40:00Z",
          last_upgrade_progress: { step: "writing" },
        },
        now,
      ),
    ).toBe(false);
  });
  it("is not cancellable once staged (clearing does not disarm next-boot)", () => {
    expect(
      hostUpgradeActivity(
        {
          last_upgrade_state: "done",
          last_upgrade_progress: {
            step: "reboot-pending",
            staged_boot_id: "b00t",
          },
        },
        now,
      ),
    ).toBe("staged");
    // Booted into it (a trial boot awaiting commit): not pending any more.
    expect(
      hostUpgradeActivity(
        {
          current_slot: "slot_b",
          last_upgrade_state: "done",
          last_upgrade_progress: {
            step: "reboot-pending",
            staged_slot: "slot_b",
            staged_boot_id: "b00t",
          },
        },
        now,
      ),
    ).toBeNull();
    // An older runner's done can outlive its reboot; not counted.
    expect(
      upgradeStartedOnHost(
        {
          last_upgrade_state: "done",
          last_upgrade_progress: { step: "reboot-pending" },
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

/**
 * @vitest-environment jsdom
 *
 * DaemonStateChip / DaemonStateBanner (#1067) — when a server row says its
 * daemon is not serving.
 *
 * The first cut re-derived that from `daemon_status`, so every `degraded`
 * rendered — including the one both agents report after a routine config
 * revert, while the daemon is up on its last-known-good config. That drew a
 * red "not serving" chip next to the config-apply chip for the same event,
 * with the alert (correctly) silent. Both components now render from the
 * server's `daemon_not_serving` alone; these cases pin that, because the bug
 * was a condition, and neither review nor `tsc` sees a wrong condition.
 */

import { describe, expect, it, afterEach } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { DaemonStateBanner, DaemonStateChip } from "./DaemonStateChip";

afterEach(cleanup);

const DEFERRED = {
  daemon_status: "degraded",
  daemon_reason: "start deferred, no bundle yet",
  daemon_status_since: "2026-09-21T12:00:00.000Z",
  daemon_not_serving: true,
};

describe.each([
  ["chip", DaemonStateChip],
  ["banner", DaemonStateBanner],
] as const)("%s", (_name, Component) => {
  it("renders when the server says the daemon is not serving", () => {
    render(<Component server={DEFERRED} />);
    expect(screen.getByText(/Daemon degraded/)).toBeTruthy();
  });

  it("stays silent on a degraded that echoes a failed config apply", () => {
    const { container } = render(
      <Component
        server={{
          ...DEFERRED,
          daemon_reason: "config_apply_reverted: named-checkconf failed",
          daemon_not_serving: false,
        }}
      />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("stays silent on ok", () => {
    const { container } = render(
      <Component
        server={{
          daemon_status: "ok",
          daemon_reason: null,
          daemon_status_since: null,
          daemon_not_serving: false,
        }}
      />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("stays silent when never reported — unknown is not an alarm", () => {
    const { container } = render(
      <Component
        server={{
          daemon_status: null,
          daemon_reason: null,
          daemon_status_since: null,
          daemon_not_serving: null,
        }}
      />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("does not second-guess the server from daemon_status alone", () => {
    // `daemon_not_serving` absent (an older response shape): render nothing
    // rather than fall back to reading `degraded` as not serving.
    const { container } = render(
      <Component
        server={{
          daemon_status: "degraded",
          daemon_reason: "start deferred, no bundle yet",
        }}
      />,
    );
    expect(container.innerHTML).toBe("");
  });
});

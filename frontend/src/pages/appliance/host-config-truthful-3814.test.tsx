/**
 * @vitest-environment jsdom
 *
 * #3814 / #3818: the Fleet's host-config apply health names the failing
 * plane's own runner log, and a first fire reads "applying", not "retrying".
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { ApplianceRow } from "@/lib/api";
import { ApplianceHostConfigHealthSection } from "./FleetTab";

afterEach(cleanup);

const row = (health: Record<string, unknown>) =>
  ({ host_config_health: health }) as unknown as ApplianceRow;

describe("host-config apply health", () => {
  it("names the failing plane's own log (#3814)", () => {
    render(
      <ApplianceHostConfigHealthSection
        row={row({
          snmp: { state: "failing", attempts: 3, at: null },
        })}
      />,
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("/var/log/spatiumddi/snmp-reload.log");
    expect(text).not.toContain("chrony-reload.log");
  });

  it("maps planes whose runner name differs, and the journal-only firewall", () => {
    render(
      <ApplianceHostConfigHealthSection
        row={row({
          resolver: { state: "failing", attempts: 3, at: null },
          firewall: { state: "failing", attempts: 3, at: null },
        })}
      />,
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("/var/log/spatiumddi/resolved-reload.log");
    expect(text).toContain("journalctl -u spatium-firewall-reload");
  });

  it("shows a first fire as applying, not retrying (#3818)", () => {
    render(
      <ApplianceHostConfigHealthSection
        row={row({ snmp: { state: "applying", attempts: 1, at: null } })}
      />,
    );
    expect(screen.getByText("applying")).toBeTruthy();
    expect(screen.queryByText(/retrying/)).toBeNull();
  });
});

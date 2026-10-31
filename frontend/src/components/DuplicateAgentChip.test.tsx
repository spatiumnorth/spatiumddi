/**
 * @vitest-environment jsdom
 *
 * DuplicateAgentChip — a second live agent process polls as this server
 * (#2044 DNS, #3143 DHCP). The chip renders only while the server row says an
 * episode is current, and its tooltip names the right agent family: the DHCP
 * row used to have no chip at all, so a cloned Kea VM was invisible there.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { DuplicateAgentChip } from "./DuplicateAgentChip";

afterEach(cleanup);

const ACTIVE = {
  duplicate_agent: true,
  duplicate_agent_since: "2026-10-30T12:00:00.000Z",
  duplicate_agent_ip: "10.0.0.9",
};

describe("DuplicateAgentChip", () => {
  it("stays silent when no episode is current", () => {
    const { container } = render(
      <DuplicateAgentChip
        server={{ duplicate_agent: false, duplicate_agent_ip: null }}
        kind="DHCP"
      />,
    );
    expect(container.textContent).toBe("");
  });

  it("names DHCP agents on a DHCP server row", () => {
    render(<DuplicateAgentChip server={ACTIVE} kind="DHCP" />);
    const chip = screen.getByText("Duplicate agent");
    const title = chip.getAttribute("title") ?? "";
    expect(title).toMatch(/^Two DHCP agent processes/);
    expect(title).toContain("10.0.0.9");
  });

  it("still names DNS agents by default", () => {
    render(<DuplicateAgentChip server={ACTIVE} />);
    const title = screen.getByText("Duplicate agent").getAttribute("title");
    expect(title).toMatch(/^Two DNS agent processes/);
  });
});

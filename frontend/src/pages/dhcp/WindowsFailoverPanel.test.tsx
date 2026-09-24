/**
 * @vitest-environment jsdom
 *
 * Windows DHCP failover panel (#1110).
 *
 * The panel's job is to make the one dangerous state — two Windows servers
 * serving a scope with no failover relationship between them — impossible to
 * miss, and to stay out of the way on every group where it cannot happen.
 * Both halves are wiring a reviewer cannot see: a verdict filter that drops
 * `uncoordinated`, or a guard that renders the panel on a Kea-only group.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type {
  DHCPFailoverRelationship,
  DHCPGroupFailover,
  DHCPScopeServing,
} from "@/lib/api";

const report = vi.fn();
vi.mock("./windowsFailover", () => ({
  GROUP_FAILOVER_QUERY_KEY: "dhcp-group-failover",
  useGroupFailover: () => ({ data: report(), isLoading: false }),
}));
vi.mock("@/lib/api", () => ({ dhcpApi: {} }));

function withClient(ui: ReactElement) {
  return render(
    <QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>,
  );
}

const { ServingVerdictTag, WindowsFailoverPanel } =
  await import("./WindowsFailoverPanel");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function serving(overrides: Partial<DHCPScopeServing> = {}): DHCPScopeServing {
  return {
    scope_id: "s-1",
    cidr: "10.1.2.0/24",
    verdict: "single_server",
    safe: true,
    detail: "Served by dhcp1 only.",
    relationship_name: null,
    relationship_mode: null,
    drift: null,
    servers: [],
    ...overrides,
  };
}

function group(overrides: Partial<DHCPGroupFailover> = {}): DHCPGroupFailover {
  return {
    group_id: "g-1",
    windows_member_count: 2,
    kea_members: [],
    members: [],
    relationships: [],
    scopes: [],
    ...overrides,
  };
}

describe("WindowsFailoverPanel", () => {
  it("renders nothing for a group without Windows members", () => {
    report.mockReturnValue(group({ windows_member_count: 0 }));
    const { container } = render(<WindowsFailoverPanel groupId="g-1" />);
    expect(container.innerHTML).toBe("");
  });

  it("lists an uncoordinated scope with its explanation", () => {
    report.mockReturnValue(
      group({
        scopes: [
          serving({ cidr: "10.1.2.0/24" }),
          serving({
            scope_id: "s-2",
            cidr: "10.9.9.0/24",
            verdict: "uncoordinated",
            safe: false,
            detail: "Held by dhcp1 and dhcp2 … can hand out the same address.",
          }),
        ],
      }),
    );
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(screen.getByText("1 scope needs attention")).toBeTruthy();
    expect(screen.getByText("10.9.9.0/24")).toBeTruthy();
    // The safe scope is not in the attention list.
    expect(screen.queryByText("10.1.2.0/24")).toBeNull();
    expect(screen.getByText(/can hand out the same address/)).toBeTruthy();
  });

  it("flags a safe failover scope whose partners have drifted", () => {
    report.mockReturnValue(
      group({
        scopes: [
          serving({
            verdict: "failover",
            relationship_name: "dhcp1-dhcp2",
            drift: true,
            detail: "Coordinated by failover relationship 'dhcp1-dhcp2'.",
          }),
        ],
      }),
    );
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(screen.getByText("1 scope needs attention")).toBeTruthy();
    expect(screen.getByText("Config drift")).toBeTruthy();
  });

  it("says why a member's view is stale instead of hiding it", () => {
    report.mockReturnValue(
      group({
        members: [
          {
            server_id: "a",
            server_name: "dhcp1",
            host: "dhcp1",
            scopes_observed_at: new Date().toISOString(),
            failover_observed_at: null,
            failover_error: "Access is denied.",
            fresh: true,
            relationship_count: 0,
          },
        ],
      }),
    );
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(screen.getByText(/Access is denied\./)).toBeTruthy();
  });

  it("shows a relationship whose partner is outside the group", () => {
    report.mockReturnValue(
      group({
        relationships: [
          {
            name: "dhcp1-dhcp9",
            mode: "HotStandby",
            max_client_lead_time_seconds: 3600,
            state_switch_interval_seconds: null,
            auto_state_transition: false,
            enable_auth: true,
            scope_ids: ["10.1.2.0"],
            complete: false,
            partner_outside_group: "dhcp9.elsewhere",
            sides: [
              {
                server_id: "a",
                server_name: "dhcp1",
                partner_server: "dhcp9.elsewhere",
                partner_server_id: null,
                server_role: "Active",
                state: "Normal",
                load_balance_percent: null,
                reserve_percent: 5,
                modified_at: new Date().toISOString(),
              },
            ],
          },
        ],
      }),
    );
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(
      screen.getByText("partner dhcp9.elsewhere not in group"),
    ).toBeTruthy();
    expect(screen.getByText("Hot standby")).toBeTruthy();
    expect(screen.getByText("1 h")).toBeTruthy();
  });
});

function pair(overrides: Partial<DHCPFailoverRelationship> = {}) {
  const side = (id: string, name: string, partner: string) => ({
    server_id: id,
    server_name: name,
    partner_server: partner,
    partner_server_id: null,
    server_role: null,
    state: "Normal",
    load_balance_percent: 50,
    reserve_percent: null,
    modified_at: new Date().toISOString(),
  });
  return {
    name: "dhcp1-dhcp2",
    mode: "LoadBalance",
    max_client_lead_time_seconds: 3600,
    state_switch_interval_seconds: null,
    auto_state_transition: false,
    enable_auth: true,
    scope_ids: ["10.1.2.0"],
    complete: true,
    partner_outside_group: null,
    sides: [side("a", "dhcp1", "dhcp2"), side("b", "dhcp2", "dhcp1")],
    ...overrides,
  };
}

describe("WindowsFailoverPanel management (#1110 Phase 2)", () => {
  it("offers a new relationship only when there are two members to pair", () => {
    report.mockReturnValue(group({ windows_member_count: 1 }));
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(screen.queryByText("+ New relationship")).toBeNull();
    cleanup();
    report.mockReturnValue(group());
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(screen.getByText("+ New relationship")).toBeTruthy();
  });

  it("warns loudly about Kea members in the same group", () => {
    report.mockReturnValue(group({ kea_members: ["kea1"] }));
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect(screen.getByText(/also has Kea members \(kea1\)/)).toBeTruthy();
  });

  it("deleting a relationship names the partner whose copy goes, and needs an acknowledgement", () => {
    report.mockReturnValue(group({ relationships: [pair()] }));
    withClient(<WindowsFailoverPanel groupId="g-1" />);
    fireEvent.click(screen.getByText("Delete"));
    const submit = screen.getByText("Delete relationship") as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    // Keeping dhcp1 (the default, lowest-named) deletes dhcp2's copy.
    expect(screen.getByText("dhcp2", { selector: "strong" })).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/partner's copy is deleted/));
    expect(submit.disabled).toBe(false);
  });

  it("does not offer scope changes on a relationship whose partner is outside the group", () => {
    report.mockReturnValue(
      group({
        relationships: [
          pair({
            complete: false,
            partner_outside_group: "dhcp9",
            sides: [pair().sides[0]],
          }),
        ],
      }),
    );
    render(<WindowsFailoverPanel groupId="g-1" />);
    expect((screen.getByText("Add scopes") as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect(screen.queryByLabelText(/Remove 10.1.2.0/)).toBeNull();
  });
});

describe("ServingVerdictTag", () => {
  it("never communicates the verdict by colour alone", () => {
    render(
      <ServingVerdictTag
        serving={serving({ verdict: "uncoordinated", safe: false })}
      />,
    );
    // Text label present, and the explanation rides on the title.
    const label = screen.getByText("Uncoordinated");
    expect(label.closest("[title]")?.getAttribute("title")).toBe(
      "Served by dhcp1 only.",
    );
  });
});

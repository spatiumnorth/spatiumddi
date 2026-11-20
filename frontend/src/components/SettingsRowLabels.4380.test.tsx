/**
 * @vitest-environment jsdom
 *
 * The seven appliance settings sections drew each row's label as a bare
 * <div> tied to nothing (#4380): a screen reader announced "combobox" with no
 * name, and clicking the label did not focus the control. Each row below must
 * resolve its label to the real control via getByLabelText.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { PlatformSettings } from "@/lib/api";

vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ setQueryData: vi.fn(), invalidateQueries: vi.fn() }),
  useQuery: () => ({ data: undefined }),
  useMutation: () => ({ isPending: false, isError: false, mutate: vi.fn() }),
}));

import { NTPSection } from "./NTPSection";
import { SNMPSection } from "./SNMPSection";
import { LLDPSection } from "./LLDPSection";
import { SyslogSection } from "./SyslogSection";
import { AptSection } from "./AptSection";
import { SSHSection } from "./SSHSection";
import { ResolverSection } from "./ResolverSection";

afterEach(cleanup);

const values = {
  ntp_source_mode: "mixed",
  ntp_allow_clients: true,
  snmp_enabled: true,
  snmp_version: "v2c",
  snmp_community_set: false,
  lldp_enabled: true,
  lldp_tx_interval: 30,
  lldp_tx_hold: 4,
  lldp_protocols: ["cdp"],
  lldp_interface_pattern: "",
  lldp_management_pattern: "",
  lldp_sys_name: "",
  lldp_sys_description: "",
  lldp_snmp_agentx: false,
  syslog_enabled: true,
  syslog_buffer_disk: false,
  apt_managed: true,
  apt_unattended_upgrades_enabled: true,
  apt_unattended_automatic_reboot: true,
  ssh_password_auth_enabled: true,
  ssh_allow_root_login: false,
  ssh_port: 22,
  resolver_mode: "override",
  resolver_dnssec: "allow-downgrade",
  resolver_dns_over_tls: "no",
} as unknown as PlatformSettings;

const props = {
  values,
  isSuperadmin: true,
  applianceMode: true,
  inputCls: "x",
};

type Row = [string, string, string | null];
// [label, expected tag, expected role (null = native role)]
const cases: [string, React.ReactElement, Row[]][] = [
  [
    "NTP",
    <NTPSection key="n" {...props} />,
    [
      ["Source mode", "SELECT", null],
      ["Pool servers", "INPUT", null],
      ["Serve NTP to clients", "BUTTON", "switch"],
      ["Allowed client CIDRs", "INPUT", null],
    ],
  ],
  [
    "SNMP",
    <SNMPSection key="s" {...props} />,
    [
      ["Enable SNMP", "BUTTON", "switch"],
      ["Version", "SELECT", null],
      ["Allowed source CIDRs", "INPUT", null],
      ["sysContact", "INPUT", null],
      ["sysLocation", "INPUT", null],
    ],
  ],
  [
    "LLDP",
    <LLDPSection key="l" {...props} />,
    [
      ["Enable LLDP", "BUTTON", "switch"],
      ["Transmit interval (s)", "INPUT", null],
      ["Interface pattern", "INPUT", null],
      ["MED location (ELIN)", "INPUT", null],
    ],
  ],
  [
    "Syslog",
    <SyslogSection key="y" {...props} />,
    [
      ["Forward logs off-box", "BUTTON", "switch"],
      ["Filter (rsyslog selector)", "INPUT", null],
      ["Disk-assisted buffering", "BUTTON", "switch"],
    ],
  ],
  [
    "Apt",
    <AptSection key="a" {...props} />,
    [
      ["Manage APT with SpatiumDDI", "BUTTON", "switch"],
      ["Unattended security upgrades", "BUTTON", "switch"],
      ["Reboot time", "INPUT", null],
    ],
  ],
  [
    "SSH",
    <SSHSection key="h" {...props} />,
    [
      ["Password authentication", "BUTTON", "switch"],
      ["Permit root login", "BUTTON", "switch"],
      ["SSH port", "INPUT", null],
    ],
  ],
  [
    "Resolver",
    <ResolverSection key="r" {...props} />,
    [
      ["Resolver mode", "SELECT", null],
      ["DNS servers", "INPUT", null],
      ["DNSSEC", "SELECT", null],
      ["DNS-over-TLS", "SELECT", null],
    ],
  ],
];

describe(
  "settings rows name their controls (#4380)",
  { timeout: 30000 },
  () => {
    for (const [name, el, rows] of cases) {
      it(`${name}: each label resolves to its control`, () => {
        render(el);
        for (const [label, tag, role] of rows) {
          const ctl = screen.getByLabelText(label, { exact: true });
          expect(ctl.tagName, label).toBe(tag);
          if (role) expect(ctl.getAttribute("role"), label).toBe(role);
        }
      });
    }

    it("SNMP community row is a group whose input has its own name", () => {
      render(<SNMPSection {...props} />);
      const group = screen.getByRole("group", {
        name: "Community string (v2c)",
      });
      expect(group.contains(screen.getByLabelText("Community string"))).toBe(
        true,
      );
    });

    it("a multi-control row is a labelled group", () => {
      render(<LLDPSection {...props} />);
      const group = screen.getByRole("group", { name: "Also receive" });
      expect(group.querySelectorAll("input[type=checkbox]").length).toBe(4);
      // each checkbox keeps its own name from its wrapping <label>
      expect(screen.getByLabelText(/CDP/)).toBeTruthy();
    });
  },
);

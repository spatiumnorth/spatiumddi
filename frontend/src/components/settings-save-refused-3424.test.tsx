/**
 * @vitest-environment jsdom
 *
 * A Fleet services section whose save the server refuses says the server's
 * reason (#3424). Every section here saves through `PUT /api/v1/settings`,
 * whose refusals are a 422 from a `SettingsUpdate` field validator (an LLDP
 * transmit interval out of range, an NTP or SNMP client CIDR that is not a
 * network, a resolver entry that is not an IP, a syslog filter with a
 * character rsyslog must not see) and, on a demo instance, a 403 with a
 * sentence. On an AxiosError `err.message` is only "Request failed with
 * status code N", so a section that shows it tells the operator who typed
 * one bad value nothing about which one. APT (#1384) and SSH (#1009) already
 * render the refusal through the shared formatter; they stay in this file as
 * the reference the other five are held to.
 *
 * Each case answers the save the way that route does and reads the line the
 * section then shows.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ComponentType } from "react";
import type { PlatformSettings } from "@/lib/api";

const update = vi.fn();
const updateApt = vi.fn();

vi.mock("@/lib/api", async () => {
  // The REAL formatters: a stub would pass whatever err.message the section
  // read and hide exactly the defect this file exists for.
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: {
      update: (p: unknown) => update(p),
      updateApt: (p: unknown) => updateApt(p),
    },
    // SSHSection reads the door report; leave it unanswered, as the form
    // renders without it.
    applianceApi: { getRemoteAccess: () => new Promise(() => {}) },
  };
});

const { LLDPSection } = await import("./LLDPSection");
const { NTPSection } = await import("./NTPSection");
const { ResolverSection } = await import("./ResolverSection");
const { SyslogSection } = await import("./SyslogSection");
const { SNMPSection } = await import("./SNMPSection");
const { AptSection } = await import("./AptSection");
const { SSHSection } = await import("./SSHSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

/** What the sections read from the platform settings. */
const VALUES = {
  lldp_enabled: true,
  lldp_tx_interval: 30,
  lldp_tx_hold: 4,
  lldp_protocols: [],
  lldp_interface_pattern: "",
  lldp_management_pattern: "",
  lldp_sys_name: "",
  lldp_sys_description: "",
  lldp_snmp_agentx: false,
  lldp_med_location: null,
  ntp_source_mode: "pool",
  ntp_pool_servers: ["pool.ntp.org"],
  ntp_custom_servers: [],
  ntp_allow_clients: true,
  ntp_allow_client_networks: ["10.0.0.0/8"],
  resolver_mode: "override",
  resolver_servers: ["1.1.1.1"],
  resolver_fallback_servers: [],
  resolver_search_domains: [],
  resolver_dnssec: "allow-downgrade",
  resolver_dns_over_tls: "no",
  syslog_enabled: true,
  syslog_targets: [],
  syslog_filter: "*.*",
  syslog_buffer_disk: false,
  snmp_enabled: true,
  snmp_version: "v2c",
  snmp_community_set: false,
  snmp_v3_users: [],
  snmp_allowed_sources: ["10.0.0.0/8"],
  snmp_sys_contact: "",
  snmp_sys_location: "",
  apt_managed: true,
  apt_sources: [],
  apt_gpg_keys: [],
  apt_proxy_http: "",
  apt_proxy_https: "",
  apt_proxy_no_proxy: "",
  apt_auth: [],
  apt_unattended_upgrades_enabled: false,
  apt_unattended_origins: [],
  apt_unattended_blocklist: [],
  apt_unattended_automatic_reboot: false,
  apt_unattended_reboot_time: "02:00",
  ssh_authorized_keys: [],
  ssh_password_auth_enabled: true,
  ssh_allow_root_login: false,
  ssh_port: 22,
  ssh_allowed_source_networks: [],
  ssh_lockdown: false,
} as unknown as PlatformSettings;

/** The shape an AxiosError has: `message` is the generic status line, and
 *  the server's answer lives under `response.data.detail`. */
function refused(status: number, detail: unknown) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    response: { status, data: { detail } },
  });
}

type Refusal = { error: Error; reason: string };

/** FastAPI's 422 for a `SettingsUpdate` field validator's ValueError. */
function invalid(field: string, input: unknown, reason: string): Refusal {
  return {
    error: refused(422, [
      {
        type: "value_error",
        loc: ["body", field],
        msg: `Value error, ${reason}`,
        input,
        ctx: { error: {} },
      },
    ]),
    reason,
  };
}

/** `forbid_in_demo_mode("Platform settings updates are disabled")`. */
const DEMO_REASON =
  "Platform settings updates are disabled (this instance is running in demo mode)";
const demo: Refusal = { error: refused(403, DEMO_REASON), reason: DEMO_REASON };

type Props = {
  values: PlatformSettings;
  isSuperadmin: boolean;
  applianceMode: boolean;
  inputCls: string;
};

interface Case {
  section: string;
  Component: ComponentType<Props>;
  /** Make the form dirty with the value the validator refuses. */
  edit: (root: HTMLElement) => void;
  save: string;
  /** The save's `settingsApi` call: `update`, or `updateApt` (the same
   *  `PUT /settings`). */
  call?: typeof update;
  /** The section's own field-validator refusal, if it has a plain input. */
  validator?: Refusal;
}

const typeInto = (input: Element | null, value: string) =>
  fireEvent.change(input as HTMLInputElement, { target: { value } });

const CASES: Case[] = [
  {
    section: "LLDP",
    Component: LLDPSection,
    edit: (root) =>
      typeInto(root.querySelector('input[type="number"]'), "5000"),
    save: "Save LLDP settings",
    validator: invalid(
      "lldp_tx_interval",
      5000,
      "lldp_tx_interval must be 1..3600 seconds",
    ),
  },
  {
    section: "NTP",
    Component: NTPSection,
    edit: () =>
      typeInto(
        screen.getByPlaceholderText("10.0.0.0/8, 192.168.0.0/16"),
        "10.0.0.0/33",
      ),
    save: "Save NTP settings",
    validator: invalid(
      "ntp_allow_client_networks",
      ["10.0.0.0/33"],
      "invalid CIDR: '10.0.0.0/33' ('10.0.0.0/33' does not appear to be an IPv4 or IPv6 network)",
    ),
  },
  {
    section: "DNS resolver",
    Component: ResolverSection,
    edit: () =>
      typeInto(screen.getByPlaceholderText("1.1.1.1, 9.9.9.9"), "1.1.1.300"),
    save: "Save resolver settings",
    validator: invalid(
      "resolver_servers",
      ["1.1.1.300"],
      "invalid resolver IP: '1.1.1.300'",
    ),
  },
  {
    section: "Syslog",
    Component: SyslogSection,
    edit: () => typeInto(screen.getByPlaceholderText("*.*"), "*.*|kern.*"),
    save: "Save syslog settings",
    validator: invalid(
      "syslog_filter",
      "*.*|kern.*",
      "syslog_filter may only contain letters, digits, and * . , ; : = ! - _ space",
    ),
  },
  {
    section: "SNMP",
    Component: SNMPSection,
    edit: () =>
      typeInto(
        screen.getByPlaceholderText("10.0.0.0/8, 192.168.0.0/16"),
        "10.0.0.0/33",
      ),
    save: "Save SNMP settings",
    validator: invalid(
      "snmp_allowed_sources",
      ["10.0.0.0/33"],
      "invalid CIDR or host: '10.0.0.0/33' ('10.0.0.0/33' does not appear to be an IPv4 or IPv6 network)",
    ),
  },
  {
    section: "APT (the reference, #1384)",
    Component: AptSection,
    edit: () =>
      typeInto(
        screen.getByPlaceholderText("HTTP proxy (http://proxy.internal:3128/)"),
        "proxy.internal:3128",
      ),
    save: "Save",
    call: updateApt,
    validator: invalid(
      "apt_proxy_http",
      "proxy.internal:3128",
      "proxy URL must start with http:// or https://",
    ),
  },
  {
    section: "SSH (the reference, #1009)",
    Component: SSHSection,
    edit: (root) =>
      typeInto(root.querySelector('input[type="number"]'), "2222"),
    save: "Save SSH settings",
  },
];

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Render the section, edit it, press its Save against `refusal`, and
 *  return the line the section then shows. */
async function saveRefused(c: Case, refusal: Refusal) {
  (c.call ?? update).mockRejectedValueOnce(refusal.error);
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const { container } = render(
    <QueryClientProvider client={qc}>
      <c.Component
        values={VALUES}
        isSuperadmin
        applianceMode
        inputCls="input"
      />
    </QueryClientProvider>,
  );
  c.edit(container);
  fireEvent.click(screen.getByRole("button", { name: c.save }));
  const line = await screen.findByText(
    new RegExp(`${escape(refusal.reason)}|Request failed with status code`),
  );
  expect(c.call ?? update).toHaveBeenCalledTimes(1);
  return line.textContent ?? "";
}

for (const c of CASES) {
  describe(`the ${c.section} section's save, refused`, () => {
    if (c.validator) {
      const v = c.validator;
      it("says which value the server refused (422)", async () => {
        const said = await saveRefused(c, v);
        expect({ said }).toEqual({ said: expect.stringContaining(v.reason) });
        expect(said).not.toContain("Request failed with status code");
      });
    }

    it("says why the server refused it (403)", async () => {
      const said = await saveRefused(c, demo);
      expect({ said }).toEqual({ said: expect.stringContaining(DEMO_REASON) });
      expect(said).not.toContain("Request failed with status code");
    });
  });
}

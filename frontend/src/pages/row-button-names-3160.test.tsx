/**
 * @vitest-environment jsdom
 *
 * The Edit and Delete buttons on a row carry an accessible name that says
 * what they do and to which item (#3160). They were pencil and bin icons
 * with no text, and the permission gate only adds a `title` while the
 * button is DENIED, so a user allowed to press them heard just "button".
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
// Whether the signed-in user may press the row's buttons. The gate adds a
// `title` (the refusal reason) only when they may not.
const perm = { allowed: true };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => perm.allowed,
      isSuperadmin: perm.allowed,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { ServerScopesTab, ClientClassesTab, OptionTemplatesTab } =
  await import("@/pages/dhcp/DHCPPage");
const { IPAMTemplatesPage } = await import("@/pages/admin/IPAMTemplatesPage");

afterEach(() => {
  cleanup();
  perm.allowed = true;
  for (const k of Object.keys(answers)) delete answers[k];
});

function show(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const STAMP = "2026-10-03T00:00:00Z";

describe("row Edit / Delete buttons are named for their item", () => {
  it("DHCP scopes", async () => {
    answers.dhcpApi = {
      listScopesByGroup: async () => [
        {
          id: "sc1",
          subnet_id: "sn1",
          group_id: "g1",
          name: "office-lan",
          description: "",
          enabled: true,
          lease_time: 3600,
          address_family: "ipv4",
          pools: [],
          static_assignments: [],
          options: {},
        },
      ],
      listGroups: async () => [],
    };
    answers.ipamApi = { listSubnets: async () => [] };
    show(<ServerScopesTab groupId="g1" />);
    expect(
      await screen.findByRole("button", { name: "Edit scope office-lan" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Delete scope office-lan" }),
    ).toBeTruthy();
  });

  it("DHCP client classes", async () => {
    answers.dhcpApi = {
      listClientClasses: async () => [
        {
          id: "c1",
          group_id: "g1",
          name: "VOIP",
          description: "",
          match_expression: "x",
          address_family: "ipv4",
          options: {},
          created_at: STAMP,
          modified_at: STAMP,
        },
      ],
    };
    show(<ClientClassesTab groupId="g1" />);
    expect(
      await screen.findByRole("button", { name: "Edit client class VOIP" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Delete client class VOIP" }),
    ).toBeTruthy();
  });

  it("keeps the name for a user the gate refuses", async () => {
    perm.allowed = false;
    answers.dhcpApi = {
      listClientClasses: async () => [
        {
          id: "c1",
          group_id: "g1",
          name: "VOIP",
          description: "",
          match_expression: "x",
          address_family: "ipv4",
          options: {},
          created_at: STAMP,
          modified_at: STAMP,
        },
      ],
    };
    show(<ClientClassesTab groupId="g1" />);
    const edit = (await screen.findByRole("button", {
      name: "Edit client class VOIP",
    })) as HTMLButtonElement;
    const del = screen.getByRole("button", {
      name: "Delete client class VOIP",
    }) as HTMLButtonElement;
    // Disabled, with the refusal reason as the tooltip, and still named.
    expect(edit.disabled).toBe(true);
    expect(edit.title).toMatch(/^Requires write permission/);
    expect(del.disabled).toBe(true);
    expect(del.title).toMatch(/^Requires delete permission/);
  });

  it("DHCP option templates", async () => {
    answers.dhcpApi = {
      listOptionTemplates: async () => [
        {
          id: "t1",
          group_id: "g1",
          name: "pxe-boot",
          description: "",
          address_family: "ipv4",
          options: {},
          created_at: STAMP,
          modified_at: STAMP,
        },
      ],
    };
    show(<OptionTemplatesTab groupId="g1" />);
    expect(
      await screen.findByRole("button", {
        name: "Edit option template pxe-boot",
      }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Delete option template pxe-boot" }),
    ).toBeTruthy();
  });

  it("IPAM templates", async () => {
    answers.ipamApi = {
      listTemplates: async () => [
        {
          id: "p1",
          name: "branch-site",
          description: "",
          applies_to: "subnet",
          tags: {},
          custom_fields: {},
          dns_group_id: null,
          dns_zone_id: null,
          dns_additional_zone_ids: null,
          dhcp_group_id: null,
          ddns_enabled: false,
          ddns_hostname_policy: "client_or_generated",
          ddns_domain_override: null,
          ddns_ttl: null,
          child_layout: null,
          applied_count: 0,
          created_at: STAMP,
          modified_at: STAMP,
        },
      ],
    };
    show(<IPAMTemplatesPage />);
    expect(
      await screen.findByRole("button", { name: "Edit template branch-site" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Delete template branch-site" }),
    ).toBeTruthy();
  });
});

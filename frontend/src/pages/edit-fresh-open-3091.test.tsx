/**
 * @vitest-environment jsdom
 *
 * The edit dialogs #3090 left on a cached row read it fresh on open, and an
 * untouched Save sends nothing that reverts another surface's change (#3091).
 * Edit DHCP Scope and IPAM Edit address, which still sent their whole body,
 * now send only what the operator changed.
 *
 * Each dialog is handed a stale row (what the page cached) while the API
 * holds the newer value: the dialog must show the newer value, a Save with no
 * edits must send nothing, one edit must send only that field, and a failed
 * read must offer Retry instead of the stale form.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type {
  DHCPClientClass,
  DHCPOptionTemplate,
  DHCPPool,
  DHCPScope,
  DHCPServerGroup,
  IPAddress,
  IPBlock,
} from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { EditBlockModal, EditAddressModal } =
  await import("@/pages/ipam/IPAMPage");
const { CreateScopeModal } = await import("@/pages/dhcp/CreateScopeModal");
const { CreatePoolModal } = await import("@/pages/dhcp/CreatePoolModal");
const { CreateClientClassModal } =
  await import("@/pages/dhcp/CreateClientClassModal");
const { CreateOptionTemplateModal } =
  await import("@/pages/dhcp/CreateOptionTemplateModal");
const { CreateServerGroupModal } =
  await import("@/pages/dhcp/CreateServerGroupModal");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const save = () =>
  fireEvent.click(screen.getByRole("button", { name: /^Save/ }));

const upstreamDown = () =>
  Promise.reject({ response: { data: { detail: "upstream down" } } });

/** The failed-read contract every dialog shares. */
async function expectRetry(
  stale: string,
  fresh: string,
  setFail: (v: boolean) => void,
) {
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("upstream down");
  expect(screen.queryByDisplayValue(stale)).toBeNull();
  expect(screen.queryByRole("button", { name: /^Save/ })).toBeNull();
  setFail(false);
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await screen.findByDisplayValue(fresh);
  expect(screen.queryByRole("alert")).toBeNull();
}

describe("Edit IP Block (#3091)", () => {
  const stale = {
    id: "b-1",
    space_id: "sp-1",
    network: "10.0.0.0/16",
    name: "blk",
    description: "xb d1",
    custom_fields: {},
    dns_inherit_settings: true,
    dhcp_inherit_settings: true,
    do_not_probe: false,
    do_not_probe_reason: "",
  } as unknown as IPBlock;
  const fresh = { ...stale, description: "xb d2" } as IPBlock;

  it("shows the stored description; an untouched Save sends nothing", async () => {
    const updateBlock = vi.fn(() => Promise.resolve(fresh));
    answers.ipamApi = { getBlock: () => Promise.resolve(fresh), updateBlock };
    const onClose = vi.fn();
    open(<EditBlockModal block={stale} onClose={onClose} />);
    await screen.findByDisplayValue("xb d2");
    expect(screen.queryByDisplayValue("xb d1")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateBlock).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateBlock = vi.fn(() => Promise.resolve(fresh));
    answers.ipamApi = { getBlock: () => Promise.resolve(fresh), updateBlock };
    open(<EditBlockModal block={stale} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("xb d2");
    fireEvent.change(box, { target: { value: "xb d3" } });
    save();
    await waitFor(() => expect(updateBlock).toHaveBeenCalled());
    expect(updateBlock).toHaveBeenCalledWith("b-1", { description: "xb d3" });
  });

  it("a failed read offers a retry and never shows the cached row", async () => {
    let fail = true;
    answers.ipamApi = {
      getBlock: () => (fail ? upstreamDown() : Promise.resolve(fresh)),
    };
    open(<EditBlockModal block={stale} onClose={() => {}} />);
    await expectRetry("xb d1", "xb d2", (v) => (fail = v));
  });
});

describe("Edit Pool (#3091)", () => {
  const scope = {
    id: "sc-1",
    group_id: "g-1",
    address_family: "ipv4",
  } as unknown as DHCPScope;
  const pool = (name: string) =>
    ({
      id: "p-1",
      scope_id: "sc-1",
      name,
      start_ip: "10.0.0.10",
      end_ip: "10.0.0.20",
      pool_type: "dynamic",
      class_restriction: null,
      lease_time_override: null,
      options_override: null,
    }) as unknown as DHCPPool;

  it("shows the stored name; an untouched Save sends nothing", async () => {
    const updatePool = vi.fn(() => Promise.resolve(pool("x")));
    answers.dhcpApi = {
      listPools: () => Promise.resolve([pool("xp-new")]),
      updatePool,
    };
    const onClose = vi.fn();
    open(
      <CreatePoolModal scope={scope} pool={pool("xp-old")} onClose={onClose} />,
    );
    await screen.findByDisplayValue("xp-new");
    expect(screen.queryByDisplayValue("xp-old")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updatePool).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updatePool = vi.fn(() => Promise.resolve(pool("x")));
    answers.dhcpApi = {
      listPools: () => Promise.resolve([pool("xp-new")]),
      updatePool,
    };
    open(
      <CreatePoolModal
        scope={scope}
        pool={pool("xp-old")}
        onClose={() => {}}
      />,
    );
    const box = await screen.findByDisplayValue("10.0.0.20");
    fireEvent.change(box, { target: { value: "10.0.0.30" } });
    save();
    await waitFor(() => expect(updatePool).toHaveBeenCalled());
    expect(updatePool).toHaveBeenCalledWith("sc-1", "p-1", {
      end_ip: "10.0.0.30",
    });
  });

  it("a failed read offers a retry and never shows the cached row", async () => {
    let fail = true;
    answers.dhcpApi = {
      listPools: () =>
        fail ? upstreamDown() : Promise.resolve([pool("xp-new")]),
    };
    open(
      <CreatePoolModal
        scope={scope}
        pool={pool("xp-old")}
        onClose={() => {}}
      />,
    );
    await expectRetry("xp-old", "xp-new", (v) => (fail = v));
  });
});

describe("Edit Client Class (#3091)", () => {
  const klass = (match: string) =>
    ({
      id: "c-1",
      group_id: "g-1",
      name: "xc",
      description: "",
      match_expression: match,
      address_family: "ipv4",
      options: { "boot-file-name": "pxe.0" },
    }) as unknown as DHCPClientClass;

  it("shows the stored expression; an untouched Save sends nothing", async () => {
    const updateClientClass = vi.fn(() => Promise.resolve(klass("x")));
    answers.dhcpApi = {
      listClientClasses: () => Promise.resolve([klass("xc-new")]),
      updateClientClass,
    };
    const onClose = vi.fn();
    open(
      <CreateClientClassModal
        klass={klass("xc-old")}
        groupId="g-1"
        onClose={onClose}
      />,
    );
    await screen.findByDisplayValue("xc-new");
    expect(screen.queryByDisplayValue("xc-old")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateClientClass).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateClientClass = vi.fn(() => Promise.resolve(klass("x")));
    answers.dhcpApi = {
      listClientClasses: () => Promise.resolve([klass("xc-new")]),
      updateClientClass,
    };
    open(
      <CreateClientClassModal
        klass={klass("xc-old")}
        groupId="g-1"
        onClose={() => {}}
      />,
    );
    const box = await screen.findByDisplayValue("xc-new");
    fireEvent.change(box, { target: { value: "xc-newer" } });
    save();
    await waitFor(() => expect(updateClientClass).toHaveBeenCalled());
    expect(updateClientClass).toHaveBeenCalledWith("g-1", "c-1", {
      match_expression: "xc-newer",
    });
  });

  it("a failed read offers a retry and never shows the cached row", async () => {
    let fail = true;
    answers.dhcpApi = {
      listClientClasses: () =>
        fail ? upstreamDown() : Promise.resolve([klass("xc-new")]),
    };
    open(
      <CreateClientClassModal
        klass={klass("xc-old")}
        groupId="g-1"
        onClose={() => {}}
      />,
    );
    await expectRetry("xc-old", "xc-new", (v) => (fail = v));
  });
});

describe("Edit Option Template (#3091)", () => {
  const tpl = (description: string) =>
    ({
      id: "t-1",
      group_id: "g-1",
      name: "xt",
      description,
      address_family: "ipv4",
      options: { "boot-file-name": "pxe.0" },
    }) as unknown as DHCPOptionTemplate;

  it("shows the stored description; an untouched Save sends nothing", async () => {
    const updateOptionTemplate = vi.fn(() => Promise.resolve(tpl("x")));
    answers.dhcpApi = {
      listOptionTemplates: () => Promise.resolve([tpl("xt-new")]),
      listServers: () => Promise.resolve([]),
      updateOptionTemplate,
    };
    const onClose = vi.fn();
    open(
      <CreateOptionTemplateModal
        template={tpl("xt-old")}
        groupId="g-1"
        onClose={onClose}
      />,
    );
    await screen.findByDisplayValue("xt-new");
    expect(screen.queryByDisplayValue("xt-old")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateOptionTemplate).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateOptionTemplate = vi.fn(() => Promise.resolve(tpl("x")));
    answers.dhcpApi = {
      listOptionTemplates: () => Promise.resolve([tpl("xt-new")]),
      listServers: () => Promise.resolve([]),
      updateOptionTemplate,
    };
    open(
      <CreateOptionTemplateModal
        template={tpl("xt-old")}
        groupId="g-1"
        onClose={() => {}}
      />,
    );
    const box = await screen.findByDisplayValue("xt-new");
    fireEvent.change(box, { target: { value: "xt-newer" } });
    save();
    await waitFor(() => expect(updateOptionTemplate).toHaveBeenCalled());
    expect(updateOptionTemplate).toHaveBeenCalledWith("g-1", "t-1", {
      description: "xt-newer",
    });
  });

  it("a failed read offers a retry and never shows the cached row", async () => {
    let fail = true;
    answers.dhcpApi = {
      listOptionTemplates: () =>
        fail ? upstreamDown() : Promise.resolve([tpl("xt-new")]),
      listServers: () => Promise.resolve([]),
    };
    open(
      <CreateOptionTemplateModal
        template={tpl("xt-old")}
        groupId="g-1"
        onClose={() => {}}
      />,
    );
    await expectRetry("xt-old", "xt-new", (v) => (fail = v));
  });
});

describe("Edit Server Group (#3091)", () => {
  const group = (description: string) =>
    ({
      id: "g-1",
      name: "xg",
      description,
      mode: "standalone",
      dhcp_socket_mode: "direct",
      heartbeat_delay_ms: 10000,
      max_response_delay_ms: 60000,
      max_ack_delay_ms: 10000,
      max_unacked_clients: 5,
      auto_failover: true,
      lease_cache_threshold: 0,
      lease_cache_max_age: null,
      kea_thread_pool_size: 1,
      kea_packet_logging: true,
    }) as unknown as DHCPServerGroup;

  it("shows the stored description; an untouched Save sends nothing", async () => {
    const updateGroup = vi.fn(() => Promise.resolve(group("x")));
    answers.dhcpApi = {
      getGroup: () => Promise.resolve(group("xg-new")),
      updateGroup,
    };
    const onClose = vi.fn();
    open(<CreateServerGroupModal group={group("xg-old")} onClose={onClose} />);
    await screen.findByDisplayValue("xg-new");
    expect(screen.queryByDisplayValue("xg-old")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateGroup).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateGroup = vi.fn(() => Promise.resolve(group("x")));
    answers.dhcpApi = {
      getGroup: () => Promise.resolve(group("xg-new")),
      updateGroup,
    };
    open(<CreateServerGroupModal group={group("xg-old")} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("xg-new");
    fireEvent.change(box, { target: { value: "xg-newer" } });
    save();
    await waitFor(() => expect(updateGroup).toHaveBeenCalled());
    expect(updateGroup).toHaveBeenCalledWith("g-1", {
      description: "xg-newer",
    });
  });

  it("a failed read offers a retry and never shows the cached row", async () => {
    let fail = true;
    answers.dhcpApi = {
      getGroup: () =>
        fail ? upstreamDown() : Promise.resolve(group("xg-new")),
    };
    open(<CreateServerGroupModal group={group("xg-old")} onClose={() => {}} />);
    await expectRetry("xg-old", "xg-new", (v) => (fail = v));
  });
});

describe("Edit DHCP Scope sends only what changed (#3091)", () => {
  const scope = (description: string) =>
    ({
      id: "sc-1",
      subnet_id: "sn-1",
      group_id: "g-1",
      name: "s",
      description,
      enabled: true,
      lease_time: 3600,
      min_lease_time: null,
      max_lease_time: null,
      lease_cache_threshold: null,
      lease_cache_max_age: null,
      hostname_sync_mode: "on_lease",
      dns_track_dynamic_leases: true,
      pxe_profile_id: "px-1",
      address_family: "ipv4",
      options: [],
      relay_addresses: [],
    }) as unknown as DHCPScope;

  function setup() {
    const updateScope = vi.fn(() => Promise.resolve(scope("x")));
    answers.dhcpApi = {
      getScope: () => Promise.resolve(scope("xs-new")),
      listGroups: () =>
        Promise.resolve([{ id: "g-1", name: "G", mode: "standalone" }]),
      updateScope,
    };
    return updateScope;
  }

  it("an untouched Save sends nothing, so nothing reverts", async () => {
    const updateScope = setup();
    const onClose = vi.fn();
    open(<CreateScopeModal scope={scope("xs-old")} onClose={onClose} />);
    await screen.findByDisplayValue("xs-new");
    // The group pill renders once the groups list has answered; before that
    // the group select is required and empty, and the form cannot submit.
    await screen.findByText("G");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateScope).not.toHaveBeenCalled();
  });

  it("sends only the changed field: no group, no PXE detach, no options", async () => {
    const updateScope = setup();
    open(<CreateScopeModal scope={scope("xs-old")} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("xs-new");
    fireEvent.change(box, { target: { value: "xs-newer" } });
    save();
    await waitFor(() => expect(updateScope).toHaveBeenCalled());
    expect(updateScope).toHaveBeenCalledWith(
      "sc-1",
      { description: "xs-newer" },
      false,
    );
  });
});

describe("IPAM Edit address sends only what changed (#3091)", () => {
  const addr = (description: string) =>
    ({
      id: "a-1",
      subnet_id: "sn-1",
      address: "10.0.0.5",
      hostname: "host",
      description,
      mac_address: null,
      status: "allocated",
      role: null,
      reserved_until: null,
      forward_zone_id: null,
      custom_fields: { owner: "net" },
      tags: {},
    }) as unknown as IPAddress;

  it("an untouched Save sends nothing", async () => {
    const updateAddress = vi.fn(() => Promise.resolve(addr("x")));
    answers.ipamApi = {
      getAddress: () => Promise.resolve(addr("xa-new")),
      updateAddress,
    };
    const onClose = vi.fn();
    open(<EditAddressModal address={addr("xa-old")} onClose={onClose} />);
    await screen.findByDisplayValue("xa-new");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateAddress).not.toHaveBeenCalled();
  });

  it("sends only the changed field, without the custom fields or the zone", async () => {
    const updateAddress = vi.fn(() => Promise.resolve(addr("x")));
    answers.ipamApi = {
      getAddress: () => Promise.resolve(addr("xa-new")),
      updateAddress,
    };
    open(<EditAddressModal address={addr("xa-old")} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("xa-new");
    fireEvent.change(box, { target: { value: "xa-newer" } });
    save();
    await waitFor(() => expect(updateAddress).toHaveBeenCalled());
    expect(updateAddress).toHaveBeenCalledWith("a-1", {
      description: "xa-newer",
      force: false,
    });
  });
});

// ── Validation follow-ups ───────────────────────────────────────────────────
// A clear is a change too: each must reach the body as the value the endpoint
// stores (the backend contract is pinned in
// backend/tests/test_edit_dialog_partial_clears_3091.py).

describe("clears and inherit toggles go out in the diff (#3091)", () => {
  const blk = (over: Record<string, unknown>) =>
    ({
      id: "b-1",
      space_id: "sp-1",
      network: "10.0.0.0/16",
      name: "blk",
      description: "",
      custom_fields: {},
      dns_inherit_settings: true,
      dhcp_inherit_settings: true,
      dhcp_server_group_id: null,
      do_not_probe: false,
      do_not_probe_reason: "",
      ...over,
    }) as unknown as IPBlock;

  async function openDhcpTab(b: IPBlock) {
    const updateBlock = vi.fn(() => Promise.resolve(b));
    answers.ipamApi = { getBlock: () => Promise.resolve(b), updateBlock };
    answers.dhcpApi = {
      listGroups: () => Promise.resolve([{ id: "g-9", name: "dh" }]),
    };
    open(<EditBlockModal block={b} onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "DHCP" }));
    return updateBlock;
  }

  it("Edit Block: inherit off plus a group sends both", async () => {
    const updateBlock = await openDhcpTab(blk({}));
    fireEvent.click(screen.getByLabelText("Inherit from parent"));
    await screen.findByRole("option", { name: "dh" });
    fireEvent.change(screen.getByRole("combobox"), {
      target: { value: "g-9" },
    });
    save();
    await waitFor(() => expect(updateBlock).toHaveBeenCalled());
    expect(updateBlock).toHaveBeenCalledWith("b-1", {
      dhcp_inherit_settings: false,
      dhcp_server_group_id: "g-9",
    });
  });

  it("Edit Block: inherit back on sends the flag and clears the group", async () => {
    const updateBlock = await openDhcpTab(
      blk({ dhcp_inherit_settings: false, dhcp_server_group_id: "g-9" }),
    );
    fireEvent.click(screen.getByLabelText("Inherit from parent"));
    save();
    await waitFor(() => expect(updateBlock).toHaveBeenCalled());
    expect(updateBlock).toHaveBeenCalledWith("b-1", {
      dhcp_inherit_settings: true,
      dhcp_server_group_id: null,
    });
  });

  it("Edit Client Class: a blanked description goes as an empty string", async () => {
    const k = {
      id: "c-1",
      group_id: "g-1",
      name: "xc",
      description: "desk phones",
      match_expression: "m",
      address_family: "ipv4",
      options: {},
    } as unknown as DHCPClientClass;
    const updateClientClass = vi.fn(() => Promise.resolve(k));
    answers.dhcpApi = {
      listClientClasses: () => Promise.resolve([k]),
      updateClientClass,
    };
    open(<CreateClientClassModal klass={k} groupId="g-1" onClose={() => {}} />);
    fireEvent.change(await screen.findByDisplayValue("desk phones"), {
      target: { value: "" },
    });
    save();
    await waitFor(() => expect(updateClientClass).toHaveBeenCalled());
    expect(updateClientClass).toHaveBeenCalledWith("g-1", "c-1", {
      description: "",
    });
  });
});

describe("IPAM Edit address: an untouched Save that is not a no-op (#3091)", () => {
  const addr = (over: Record<string, unknown>) =>
    ({
      id: "a-1",
      subnet_id: "sn-1",
      address: "10.0.0.5",
      hostname: "host",
      description: "d",
      mac_address: "00:11:22:33:44:55",
      status: "allocated",
      role: null,
      reserved_until: null,
      forward_zone_id: null,
      custom_fields: {},
      tags: {},
      ...over,
    }) as unknown as IPAddress;

  it("a static_dhcp row with no reservation still saves, to retry it (#867)", async () => {
    const row = addr({ status: "static_dhcp", static_assignment_id: null });
    const updateAddress = vi.fn(() => Promise.resolve(row));
    answers.ipamApi = { getAddress: () => Promise.resolve(row), updateAddress };
    open(<EditAddressModal address={row} onClose={() => {}} />);
    await screen.findByDisplayValue("d");
    save();
    await waitFor(() => expect(updateAddress).toHaveBeenCalled());
    expect(updateAddress).toHaveBeenCalledWith("a-1", {
      status: "static_dhcp",
      force: false,
    });
  });

  it("a linked static_dhcp row's untouched Save still sends nothing", async () => {
    const row = addr({ status: "static_dhcp", static_assignment_id: "st-1" });
    const updateAddress = vi.fn(() => Promise.resolve(row));
    answers.ipamApi = { getAddress: () => Promise.resolve(row), updateAddress };
    const onClose = vi.fn();
    open(<EditAddressModal address={row} onClose={onClose} />);
    await screen.findByDisplayValue("d");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateAddress).not.toHaveBeenCalled();
  });

  it("a reserved-until stored with seconds is not a change", async () => {
    const row = addr({
      status: "reserved",
      reserved_until: "2030-06-01T10:30:45Z",
    });
    const updateAddress = vi.fn(() => Promise.resolve(row));
    answers.ipamApi = { getAddress: () => Promise.resolve(row), updateAddress };
    const onClose = vi.fn();
    open(<EditAddressModal address={row} onClose={onClose} />);
    await screen.findByDisplayValue("d");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateAddress).not.toHaveBeenCalled();
  });
});

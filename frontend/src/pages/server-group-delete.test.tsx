/**
 * @vitest-environment jsdom
 *
 * Delete Server Group says what the delete removes (#1399).
 *
 * The DHCP page's Delete Server Group said "The group must be empty — move
 * or delete its servers first", while the server refused only a group that
 * still held servers and hard-deleted every scope of the group, with its
 * pools and reservations, none of them into Trash. The DNS twin said "The
 * group must be empty — move or delete its servers and zones first", and a
 * zone already in Trash neither blocked the delete nor survived it.
 *
 * The server now refuses a group that holds a live scope, as DNS refuses one
 * holding a live zone. What a group delete still takes is what the operator
 * already deleted: its scopes (zones) in Trash, for good. So the dialogs
 * must not promise an empty group, and must say that.
 *
 * A dialog that knows the group still holds servers or live scopes (zones)
 * does not offer a delete the server will refuse: it says what the group
 * holds and offers no Delete, so no request is sent and no 409 is logged.
 * The server's refusal stays the backstop (another tab, the API, the
 * approval queue): a group it refuses keeps its dialog and shows the reason.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
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

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DNSPage } = await import("@/pages/dns/DNSPage");
const { DHCPPage } = await import("@/pages/dhcp/DHCPPage");

const STAMP = "2026-10-03T00:00:00Z";

const DNS_GROUP = {
  id: "grp-1",
  name: "retiring",
  description: "",
  group_type: "internal",
  default_view: null,
  is_recursive: false,
  catalog_zones_enabled: false,
  catalog_zone_name: "",
  server_drivers: [],
  created_at: STAMP,
  modified_at: STAMP,
};

const DHCP_GROUP = {
  id: "dgrp-1",
  name: "retiring",
  description: "",
  mode: "standalone",
  heartbeat_delay_ms: 10000,
  max_response_delay_ms: 60000,
  max_ack_delay_ms: 10000,
  max_unacked_clients: 5,
  auto_failover: true,
  lease_cache_threshold: 0,
  lease_cache_max_age: null,
  kea_thread_pool_size: 0,
  kea_packet_logging: false,
  kea_member_count: 0,
  servers: [],
  created_at: STAMP,
  modified_at: STAMP,
};

/** The rejection axios produces for a 409 carrying the route's `detail`. */
function conflict(detail: string) {
  return Object.assign(new Error("Request failed with status code 409"), {
    isAxiosError: true,
    status: 409,
    response: { status: 409, data: { detail } },
  });
}

function show(ui: ReactNode, url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The dialog the operator is looking at: the last one opened. */
function topDialog(): HTMLElement {
  const dialogs = screen.getAllByRole("dialog");
  return dialogs[dialogs.length - 1];
}

function words(el: HTMLElement): string {
  return (el.textContent ?? "").replace(/\s+/g, " ").trim();
}

/** A promise the server does not keep: it deletes a group whose scopes or
 *  zones are in Trash, and them with it. */
const PROMISES_EMPTY = /must be empty|only an? empty/i;

/** One sentence that says the group's `what` already in Trash are deleted
 *  with it, beyond restoring. */
function namesTrashLoss(said: string, what: RegExp): boolean {
  return said
    .split(/(?<=[.!?])\s+/)
    .some(
      (s) =>
        what.test(s) &&
        /\bTrash\b/.test(s) &&
        /for good|no longer be restored|cannot be restored/i.test(s),
    );
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  localStorage.clear();
  sessionStorage.clear();
});

describe("DHCP: Delete Server Group", () => {
  function dhcpAnswers(extra: Record<string, Answer> = {}) {
    answers.dhcpApi = {
      listGroups: async () => [DHCP_GROUP],
      listServers: async () => [],
      listScopesByGroup: async () => [],
      ...extra,
    };
  }

  it("does not promise an empty group, and names the scopes in Trash it deletes for good", async () => {
    dhcpAnswers();
    show(<DHCPPage />, "/dhcp?group=dgrp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete Group$/ }),
    );
    // The dialog first reads what the group holds, then offers the delete
    // (a new dialog element, so the top one is looked up again each try).
    await waitFor(() => within(topDialog()).getByRole("checkbox"));
    const said = words(topDialog());

    expect(said).toContain("retiring");
    expect(
      said,
      "the server deletes a group whose scopes are in Trash, so the group " +
        "does not have to be empty",
    ).not.toMatch(PROMISES_EMPTY);
    expect(
      namesTrashLoss(said, /\bscopes?\b/i),
      `the dialog never says the group's scopes in Trash go with it for good: "${said}"`,
    ).toBe(true);
  });

  it("a group still holding a live scope: says so, offers no Delete, sends nothing", async () => {
    const deleteGroup = vi.fn(() => Promise.resolve({ status: 204 }));
    dhcpAnswers({
      deleteGroup,
      listScopesByGroup: async () => [{ id: "scope-1", name: "branch-a" }],
    });
    show(<DHCPPage />, "/dhcp?group=dgrp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete Group$/ }),
    );
    await waitFor(() => within(topDialog()).getByText(/still holds 1 scope/));
    const dialog = topDialog();
    expect(
      within(dialog).queryByRole("button", { name: /^Delete/ }),
      "the dialog knows the group still holds a scope, so the server will " +
        "refuse the delete: it must not offer one",
    ).toBeNull();
    expect(words(dialog)).toMatch(/delete its scopes/i);
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(deleteGroup).not.toHaveBeenCalled();
  });

  it("a group still holding a server: says so and offers no Delete", async () => {
    const deleteGroup = vi.fn(() => Promise.resolve({ status: 204 }));
    dhcpAnswers({
      deleteGroup,
      listServers: async () => [{ id: "srv-1", name: "kea-1" }],
    });
    show(<DHCPPage />, "/dhcp?group=dgrp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete Group$/ }),
    );
    await waitFor(() => within(topDialog()).getByText(/still holds 1 server/));
    const dialog = topDialog();
    expect(
      within(dialog).queryByRole("button", { name: /^Delete/ }),
    ).toBeNull();
    expect(deleteGroup).not.toHaveBeenCalled();
  });

  it("a group the server refuses keeps its dialog and says why (control)", async () => {
    const reason =
      "DHCP server group 'retiring' still holds 1 scope(s). Delete its scopes first, then the group.";
    const deleteGroup = vi.fn(() => Promise.reject(conflict(reason)));
    dhcpAnswers({ deleteGroup });
    show(<DHCPPage />, "/dhcp?group=dgrp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete Group$/ }),
    );
    fireEvent.click(
      await waitFor(() => within(topDialog()).getByRole("checkbox")),
    );
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Delete$/ }),
    );

    await waitFor(() => expect(deleteGroup).toHaveBeenCalledWith("dgrp-1"));
    await within(topDialog()).findByText(/still holds 1 scope/);
  });
});

describe("DNS: Delete Server Group", () => {
  function dnsAnswers(extra: Record<string, Answer> = {}) {
    answers.dnsApi = {
      listGroups: async () => [DNS_GROUP],
      listZones: async () => [],
      listViews: async () => [],
      listServers: async () => [],
      ...extra,
    };
  }

  it("does not promise an empty group, and names the zones in Trash it deletes for good", async () => {
    dnsAnswers();
    show(<DNSPage />, "/dns?group=grp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /Delete Group$/ }),
    );
    let said = words(topDialog());
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Continue$/ }),
    );
    said += ` ${words(topDialog())}`;

    expect(said).toContain("retiring");
    expect(
      said,
      "the server deletes a group whose zones are in Trash, so the group " +
        "does not have to be empty",
    ).not.toMatch(PROMISES_EMPTY);
    expect(
      namesTrashLoss(said, /\bzones?\b/i),
      `the dialog never says the group's zones in Trash go with it for good: "${said}"`,
    ).toBe(true);
  });

  it("a group still holding a live zone: says so, offers no Delete, sends nothing", async () => {
    const deleteGroup = vi.fn(() => Promise.resolve({ status: 204 }));
    dnsAnswers({
      deleteGroup,
      listZones: async () => [{ id: "zone-1", name: "corp.example." }],
    });
    show(<DNSPage />, "/dns?group=grp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /Delete Group$/ }),
    );
    await waitFor(() => within(topDialog()).getByText(/still holds 1 zone/));
    const dialog = topDialog();
    expect(
      within(dialog).queryByRole("button", { name: /^(Delete|Continue)/ }),
      "the dialog knows the group still holds a zone, so the server will " +
        "refuse the delete: it must not offer one",
    ).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(deleteGroup).not.toHaveBeenCalled();
  });

  it("a group the server refuses keeps its dialog and says why (control)", async () => {
    const reason =
      "DNS server group 'retiring' still contains 1 zone(s). Delete or move them before deleting the group.";
    const deleteGroup = vi.fn(() => Promise.reject(conflict(reason)));
    dnsAnswers({ deleteGroup });
    show(<DNSPage />, "/dns?group=grp-1");

    fireEvent.click(
      await screen.findByRole("button", { name: /Delete Group$/ }),
    );
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Continue$/ }),
    );
    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: /^Delete$/ }),
    );

    await waitFor(() => expect(deleteGroup).toHaveBeenCalledWith("grp-1"));
    await within(topDialog()).findByText(/still contains 1 zone/);
  });
});

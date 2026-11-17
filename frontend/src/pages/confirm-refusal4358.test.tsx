/**
 * @vitest-environment jsdom
 *
 * A refused confirm says why inside the open dialog (#4358, the class #4353
 * started): the dialog stays open and an announced alert carries the server's
 * reason, instead of the dialog closing or sitting silent while the reason is
 * drawn on the inert page behind it.
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
import type { ReactElement } from "react";

function refused(status: number, detail: string) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    response: { status, data: { detail } },
  });
}

const TOKEN = {
  id: "t1",
  name: "ci-token",
  description: "",
  prefix: "sddi_AbCdE",
  scope: "user",
  scopes: [],
  resource_grants: [],
  user_id: "u1",
  owner_is_active: true,
  expires_at: null,
  last_used_at: null,
  is_active: true,
  created_at: "2026-10-01T00:00:00.000Z",
};
const CR = {
  id: "cr1",
  operation: "delete_subnet",
  resource_type: "subnet",
  resource_id: null,
  resource_display: "10.0.0.0/24",
  args: {},
  preview_text: "p",
  risk_reason: "r",
  state: "pending",
  requested_by_user_id: "me",
  requested_by_display: "me",
  decided_by_user_id: null,
  decided_by_display: null,
  decision_note: null,
  result: null,
  error: null,
  expires_at: "2026-12-01T00:00:00Z",
  decided_at: null,
  executed_at: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
  can_approve: true,
  approve_blocked_reason: null,
};
const FEED = {
  id: "f1",
  name: "edge-feed",
  description: "",
  enabled: true,
  kind: "ip",
  poll_path: "/api/v1/feeds/f1",
  last_polled_at: null,
  last_polled_ip: null,
  poll_count: 0,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
const HOOK = {
  id: "w1",
  name: "pager-hook",
  description: "",
  enabled: true,
  url: "https://example.invalid/hook",
  secret_set: false,
  event_types: null,
  header_names: [],
  headers_set: false,
  timeout_seconds: 10,
  max_attempts: 3,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
const BLOCKLIST = {
  id: "b1",
  name: "my-list",
  zone_suffix: "bl.example.invalid",
  category: "spam",
  description: "",
  homepage_url: null,
  enabled: true,
  return_codes: {},
  requires_registration: false,
  qps_note: "",
  is_builtin: false,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
const CLOUD = {
  id: "c1",
  name: "prod-aws",
  description: "",
  enabled: true,
  provider: "aws",
  credentials_present: true,
  provider_config: {},
  regions: [],
  ipam_space_id: "s1",
  public_space_id: null,
  dns_group_id: null,
  mirror_load_balancers: false,
  mirror_stopped_instances: false,
  sync_interval_seconds: 300,
  last_synced_at: null,
  last_sync_error: null,
  provider_account_id: null,
  network_count: null,
  instance_count: null,
  last_discovery: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};

const rejecting = (detail: string) => () =>
  Promise.reject(refused(409, detail));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: async () => ({ id: "me" }),
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    apiTokensApi: {
      ...actual.apiTokensApi,
      list: async () => [TOKEN],
      update: rejecting("Token is pinned by a deploy"),
    },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      list: async () => [CR],
      cancel: rejecting("Request already executing"),
    },
    firewallFeedsApi: {
      ...actual.firewallFeedsApi,
      list: async () => [FEED],
      rotateToken: rejecting("Feed is locked by an upstream poll"),
    },
    webhooksApi: {
      ...actual.webhooksApi,
      list: async () => [HOOK],
      listEventTypes: async () => [],
      delete: rejecting("Subscription has queued deliveries"),
    },
    dnsblApi: {
      ...actual.dnsblApi,
      listLists: async () => [BLOCKLIST],
      listPinned: async () => [],
      getSettings: async () => ({}),
      listListings: async () => [],
      deleteList: rejecting("List is referenced by a policy"),
    },
    cloudApi: {
      ...actual.cloudApi,
      listEndpoints: async () => [CLOUD],
      deleteEndpoint: rejecting("Account still owns mirrored subnets"),
    },
  };
});

vi.mock("@/hooks/usePermissions", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@/hooks/usePermissions")>();
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      hasAnyGrantFor: () => true,
      isSuperadmin: true,
      isLoading: false,
      isError: false,
      unanswered: null,
    }),
  };
});

const { ApiTokensPage } = await import("./admin/ApiTokensPage");
const { ChangeRequestsPage } = await import("./admin/ChangeRequestsPage");
const { FirewallFeedsPage } =
  await import("./firewall_feeds/FirewallFeedsPage");
const { WebhooksPage } = await import("./admin/WebhooksPage");
const { DNSBLPage } = await import("./admin/DNSBLPage");
const { CloudPage } = await import("./cloud/CloudPage");

afterEach(cleanup);

function mount(page: ReactElement) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

type Case = {
  name: string;
  page: ReactElement;
  /** Click the row control that opens the confirm. */
  open: () => Promise<void>;
  /** Text of the dialog's confirm button. */
  confirm: string;
  reason: string;
};

const byTitle = (t: string) => async () => {
  fireEvent.click(await screen.findByTitle(t));
};

const CASES: Case[] = [
  {
    name: "API tokens: Revoke",
    page: <ApiTokensPage />,
    open: byTitle("Revoke"),
    confirm: "Revoke",
    reason: "Token is pinned by a deploy",
  },
  {
    name: "Change requests: Withdraw request",
    page: <ChangeRequestsPage />,
    open: async () => {
      fireEvent.click(await screen.findByRole("button", { name: /^Cancel$/ }));
    },
    confirm: "Withdraw request",
    reason: "Request already executing",
  },
  {
    name: "Firewall feeds: Rotate token",
    page: <FirewallFeedsPage />,
    open: byTitle("Rotate token"),
    confirm: "Rotate token",
    reason: "Feed is locked by an upstream poll",
  },
  {
    name: "Webhooks: Delete subscription",
    page: <WebhooksPage />,
    open: async () => {
      fireEvent.click(await screen.findByRole("button", { name: /Delete/ }));
    },
    confirm: "Delete",
    reason: "Subscription has queued deliveries",
  },
  {
    name: "DNS blocklists: Delete blocklist",
    page: <DNSBLPage />,
    open: byTitle("Delete custom list"),
    confirm: "Delete",
    reason: "List is referenced by a policy",
  },
  {
    name: "Cloud: Delete cloud account",
    page: <CloudPage />,
    open: byTitle("Delete"),
    confirm: "Delete",
    reason: "Account still owns mirrored subnets",
  },
];

describe.each(CASES)("$name", { timeout: 15000 }, (c) => {
  it("stays open and says why the server refused", async () => {
    mount(c.page);
    await c.open();
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: c.confirm }));
    await waitFor(() =>
      expect(
        within(screen.getByRole("dialog")).getByRole("alert").textContent,
      ).toContain(c.reason),
    );
  });

  it("forgets the refusal when the dialog is closed and reopened", async () => {
    mount(c.page);
    await c.open();
    let dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: c.confirm }));
    await waitFor(() =>
      expect(
        within(screen.getByRole("dialog")).getByRole("alert"),
      ).toBeTruthy(),
    );
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Cancel",
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await c.open();
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByRole("alert")).toBeNull();
  });
});

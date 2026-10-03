/**
 * @vitest-environment jsdom
 *
 * A list whose read is refused is never shown as empty (#1343).
 *
 * Each page here reads its list from a route a user may be refused: most
 * are superadmin-only, so a read-only Viewer always is. The server answers
 * 403, and every one of these pages used to treat the missing data as an
 * empty list: "Trash is empty." over a trash holding rows, "No
 * subscriptions yet." over live webhooks, a blank Users table with no word.
 * The reader is told something false about the system, and some of the
 * pages kept polling the refused read every 30 s, each refusal an audited
 * request.
 *
 * These render each page with its list read refused the way the API
 * refuses it (a 403 carrying the route's own `detail`) and hold the page to
 * saying so. As a control, each still shows its empty state when the list
 * really is empty, so the fix is not "never say empty".
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

/** The rejection axios produces for a 403 (lib/api.ts's client). */
function refusal(detail = "Superadmin required") {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    status: 403,
    response: { status: 403, data: { detail } },
  });
}

/** Any other failure: the read was not refused, it broke. */
function serverError() {
  return Object.assign(new Error("Request failed with status code 500"), {
    isAxiosError: true,
    status: 500,
    response: { status: 500, data: { detail: "Internal Server Error" } },
  });
}

const lists = {
  trash: vi.fn(),
  users: vi.fn(),
  webhooks: vi.fn(),
  blockTargets: vi.fn(),
  blocks: vi.fn(),
  appliances: vi.fn(),
  aiTools: vi.fn(),
  cutoverPlans: vi.fn(),
  auditTargets: vi.fn(),
  influxTargets: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    trashApi: { ...actual.trashApi, list: () => lists.trash() },
    usersApi: { ...actual.usersApi, list: () => lists.users() },
    webhooksApi: {
      ...actual.webhooksApi,
      list: () => lists.webhooks(),
      listEventTypes: () => Promise.resolve([]),
    },
    blockSyncApi: {
      ...actual.blockSyncApi,
      listTargets: () => lists.blockTargets(),
      listBlocks: () => lists.blocks(),
    },
    applianceApprovalApi: {
      ...actual.applianceApprovalApi,
      list: () => lists.appliances(),
    },
    aiToolCatalogApi: {
      ...actual.aiToolCatalogApi,
      list: () => lists.aiTools(),
    },
    cutoverApi: { ...actual.cutoverApi, listPlans: () => lists.cutoverPlans() },
    settingsApi: {
      ...actual.settingsApi,
      listAuditTargets: () => lists.auditTargets(),
      listInfluxTargets: () => lists.influxTargets(),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { TrashPage } = await import("@/pages/admin/TrashPage");
const { WebhooksPage } = await import("@/pages/admin/WebhooksPage");
const { UsersPage } = await import("@/pages/admin/UsersPage");
const { BlockSyncPage } = await import("@/pages/security/BlockSyncPage");
const { NetworkToolsPage } = await import("@/pages/tools/NetworkToolsPage");
const { AIToolCatalogPage } = await import("@/pages/admin/AIToolCatalogPage");
const { CutoverPage } = await import("@/pages/admin/CutoverPage");
const { AuditForwardTargets } =
  await import("@/components/AuditForwardTargets");
const { InfluxDBTargets } = await import("@/components/InfluxDBTargets");

function show(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  for (const fn of Object.values(lists)) fn.mockReset();
});

describe("a refused list read says it was refused, never that the list is empty", () => {
  it("Trash", async () => {
    lists.trash.mockRejectedValue(refusal());
    show(<TrashPage />);
    await screen.findByText(/permission/i);
    expect(screen.getByText(/Superadmin required/)).toBeTruthy();
    expect(screen.queryByText(/Trash is empty/)).toBeNull();
  });

  it("Webhooks", async () => {
    lists.webhooks.mockRejectedValue(refusal());
    show(<WebhooksPage />);
    await screen.findByText(/permission/i);
    expect(screen.getByText(/Superadmin required/)).toBeTruthy();
    expect(screen.queryByText(/No subscriptions yet/)).toBeNull();
  });

  it("Users: the table says why it has no rows", async () => {
    lists.users.mockRejectedValue(refusal());
    show(<UsersPage />);
    await screen.findByText(/permission/i);
    expect(screen.getByText(/Superadmin required/)).toBeTruthy();
  });

  it("Security › Block Sync: both lists", async () => {
    lists.blockTargets.mockRejectedValue(refusal());
    lists.blocks.mockRejectedValue(refusal());
    show(<BlockSyncPage />);
    expect(await screen.findAllByText(/permission/i)).toHaveLength(2);
    expect(screen.queryByText(/No network blocks yet/)).toBeNull();
    expect(screen.queryByText(/No OPNsense routers/)).toBeNull();
  });

  it("Tools › Network Tools: the run-from appliances", async () => {
    lists.appliances.mockRejectedValue(refusal());
    show(<NetworkToolsPage />);
    await screen.findByText(/permission/i);
    expect(screen.queryByText(/no appliances online/)).toBeNull();
  });

  it("AI › Tools", async () => {
    lists.aiTools.mockRejectedValue(refusal());
    show(<AIToolCatalogPage />);
    await screen.findByText(/permission/i);
    expect(screen.getByText(/Superadmin required/)).toBeTruthy();
    expect(screen.queryByText(/No tools registered/)).toBeNull();
  });

  it("Cutover: the refusal, without the empty-list invitation beside it", async () => {
    lists.cutoverPlans.mockRejectedValue(refusal());
    show(<CutoverPage />);
    await screen.findByText(/Superadmin required/);
    expect(screen.queryByText(/No cutover plans yet/)).toBeNull();
  });

  it("Settings › Audit forwarding: a bare 403 still reads as a refusal", async () => {
    lists.auditTargets.mockRejectedValue(refusal("Forbidden"));
    show(<AuditForwardTargets isSuperadmin={false} />);
    await screen.findByText(/permission/i);
    expect(
      screen.queryByText(/No audit-forward targets configured/),
    ).toBeNull();
  });

  it("Settings › InfluxDB export", async () => {
    lists.influxTargets.mockRejectedValue(refusal("Forbidden"));
    show(<InfluxDBTargets isSuperadmin={false} />);
    await screen.findByText(/permission/i);
    expect(screen.queryByText(/No InfluxDB targets configured/)).toBeNull();
  });

  it("a read that failed some other way is not called empty either", async () => {
    lists.trash.mockRejectedValue(serverError());
    show(<TrashPage />);
    await screen.findByText(/Internal Server Error/);
    expect(screen.queryByText(/Trash is empty/)).toBeNull();
    expect(screen.queryByText(/permission/i)).toBeNull();
  });
});

describe("a list that really is empty still says so (control)", () => {
  it("Trash", async () => {
    lists.trash.mockResolvedValue({ items: [], total: 0 });
    show(<TrashPage />);
    await screen.findByText(/Trash is empty/);
  });

  it("Webhooks", async () => {
    lists.webhooks.mockResolvedValue([]);
    show(<WebhooksPage />);
    await screen.findByText(/No subscriptions yet/);
  });

  it("Security › Block Sync", async () => {
    lists.blockTargets.mockResolvedValue([]);
    lists.blocks.mockResolvedValue([]);
    show(<BlockSyncPage />);
    await screen.findByText(/No network blocks yet/);
    expect(screen.getByText(/No OPNsense routers/)).toBeTruthy();
  });

  it("Tools › Network Tools", async () => {
    lists.appliances.mockResolvedValue([]);
    show(<NetworkToolsPage />);
    await screen.findByText(/no appliances online/);
  });

  it("AI › Tools", async () => {
    lists.aiTools.mockResolvedValue({
      tools: [],
      total: 0,
      platform_override: null,
    });
    show(<AIToolCatalogPage />);
    await screen.findByText(/No tools registered/);
  });

  it("Cutover", async () => {
    lists.cutoverPlans.mockResolvedValue([]);
    show(<CutoverPage />);
    await screen.findByText(/No cutover plans yet/);
  });

  it("Settings › Audit forwarding", async () => {
    lists.auditTargets.mockResolvedValue([]);
    show(<AuditForwardTargets isSuperadmin />);
    await screen.findByText(/No audit-forward targets configured/);
  });

  it("Settings › InfluxDB export", async () => {
    lists.influxTargets.mockResolvedValue([]);
    show(<InfluxDBTargets isSuperadmin />);
    await screen.findByText(/No InfluxDB targets configured/);
  });
});

describe("a refused poll stops asking (each ask is a denied audit row)", () => {
  async function afterAMinute() {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(65_000);
    });
  }

  it("Security › Block Sync asks each refused list once", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    lists.blockTargets.mockRejectedValue(refusal());
    lists.blocks.mockRejectedValue(refusal());
    show(<BlockSyncPage />);
    await vi.waitFor(() => expect(lists.blocks).toHaveBeenCalledTimes(1));
    await afterAMinute();
    expect(lists.blockTargets).toHaveBeenCalledTimes(1);
    expect(lists.blocks).toHaveBeenCalledTimes(1);
  });

  it("Tools › Network Tools asks for the appliances once", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    lists.appliances.mockRejectedValue(refusal());
    show(<NetworkToolsPage />);
    await vi.waitFor(() => expect(lists.appliances).toHaveBeenCalledTimes(1));
    await afterAMinute();
    expect(lists.appliances).toHaveBeenCalledTimes(1);
  });

  it("Settings › InfluxDB export asks once", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    lists.influxTargets.mockRejectedValue(refusal("Forbidden"));
    show(<InfluxDBTargets isSuperadmin={false} />);
    await vi.waitFor(() =>
      expect(lists.influxTargets).toHaveBeenCalledTimes(1),
    );
    await afterAMinute();
    expect(lists.influxTargets).toHaveBeenCalledTimes(1);
  });

  it("a poll that is answered keeps polling (control)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    lists.blockTargets.mockResolvedValue([]);
    lists.blocks.mockResolvedValue([]);
    show(<BlockSyncPage />);
    await vi.waitFor(() => expect(lists.blocks).toHaveBeenCalledTimes(1));
    await afterAMinute();
    expect(lists.blocks.mock.calls.length).toBeGreaterThan(1);
  });
});

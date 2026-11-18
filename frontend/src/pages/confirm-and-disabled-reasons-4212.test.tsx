/**
 * @vitest-environment jsdom
 *
 * #4212 — container Stop / Restart / Start, API token Revoke and BGP Stop
 * tracking ask first (cancel calls nothing, confirm calls the API once), and
 * controls disabled for a reason other than permission say why.
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

const { ContainersTab } = await import("@/pages/appliance/ContainersTab");
const { ApiTokensPage } = await import("@/pages/admin/ApiTokensPage");
const { BgpMonitorTab } = await import("@/pages/network/BgpMonitorTab");
const { IPAMTemplatesPage } = await import("@/pages/admin/IPAMTemplatesPage");
const { BackupTargetsSection } =
  await import("@/pages/admin/BackupTargetsSection");
const { IPAMPage } = await import("@/pages/ipam/IPAMPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  for (const k of Object.keys(answers)) delete answers[k];
  try {
    sessionStorage.clear();
  } catch {
    // no storage in this jsdom: nothing to clear.
  }
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

describe("container actions confirm first", () => {
  const action = vi.fn().mockResolvedValue({});
  function open(state: string) {
    action.mockClear();
    answers.applianceContainersApi = {
      list: async () => [
        {
          name: "spatium-dns-0",
          image: "x",
          state,
          status: state,
          health: null,
          short_id: "abc",
          started_at: null,
          is_spatium: true,
        },
      ],
      action,
    };
    show(<ContainersTab />);
  }

  it("Restart: cancel calls nothing, confirm calls once", async () => {
    open("running");
    const restart = await screen.findByRole("button", { name: /^Restart$/ });
    restart.focus();
    fireEvent.click(restart);
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toMatch(/briefly unavailable on this node/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(action).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(restart);
  });

  it("Restart asks first", async () => {
    open("running");
    fireEvent.click(await screen.findByRole("button", { name: /^Restart$/ }));
    const dialog = await screen.findByRole("dialog");
    expect(action).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Restart" }));
    await waitFor(() => expect(action).toHaveBeenCalledTimes(1));
    expect(action.mock.calls[0].slice(0, 2)).toEqual([
      "spatium-dns-0",
      "restart",
    ]);
  });

  // #4232 — a pod has no Stop / Start (it would need its workload scaled).
  it("offers no Stop or Start on a running or exited pod", async () => {
    open("running");
    await screen.findByRole("button", { name: /^Restart$/ });
    expect(screen.queryByRole("button", { name: /^Stop$/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Start$/ })).toBeNull();
  });
});

describe("API token Revoke confirms first", () => {
  it("cancel does not revoke, confirm does", async () => {
    const update = vi.fn().mockResolvedValue({});
    answers.authApi = {
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    };
    answers.apiTokensApi = {
      list: async () => [
        {
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
          created_at: STAMP,
        },
      ],
      update,
    };
    show(<ApiTokensPage />);
    const revoke = await screen.findByTitle("Revoke");
    revoke.focus();
    fireEvent.click(revoke);
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toMatch(/Calls using this token fail at once/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(update).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(revoke);

    fireEvent.click(revoke);
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Revoke",
      }),
    );
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith("t1", { is_active: false });
  });
});

describe("BGP Stop tracking confirms first", () => {
  it("cancel does not delete, confirm does", async () => {
    const del = vi.fn().mockResolvedValue({});
    answers.asnsApi = {
      listTrackedPrefixes: async () => [
        {
          id: "tp-1",
          asn_id: "asn-1",
          prefix: "203.0.113.0/24",
          expected_origin_asn: 64512,
          source: "manual",
          enabled: true,
          allowed_origins: [],
          last_seen_origins: null,
          last_checked_at: null,
          next_check_at: null,
        },
      ],
      listHijacks: async () => [],
      deleteTrackedPrefix: del,
    };
    show(<BgpMonitorTab asnId="asn-1" asnKind="public" />);
    const stop = await screen.findByRole("button", { name: "Stop tracking" });
    stop.focus();
    fireEvent.click(stop);
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toMatch(/203\.0\.113\.0\/24/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(del).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(stop);

    fireEvent.click(stop);
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Stop tracking",
      }),
    );
    await waitFor(() => expect(del).toHaveBeenCalledTimes(1));
    expect(del.mock.calls[0][0]).toBe("tp-1");
  });
});

describe("disabled controls say why", () => {
  it("IPAM template Reapply with nothing applied", async () => {
    answers.ipamApi = {
      listTemplates: async () => [
        {
          id: "t1",
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
    const btn = (await screen.findByRole("button", {
      name: "Reapply across all instances",
    })) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.title).toBe("Not applied anywhere yet: nothing to reapply.");
  });

  it("backup Run now on a disabled target", async () => {
    answers.backupTargetsApi = {
      list: async () => [
        {
          id: "b1",
          name: "nas",
          description: "",
          kind: "local_volume",
          enabled: false,
          config: {},
          passphrase_set: false,
          passphrase_hint: "",
          schedule_cron: null,
          retention_keep_last_n: null,
          retention_keep_days: null,
          write_only: false,
          last_run_status: "never",
          last_run_at: null,
          last_run_filename: null,
          last_run_node: null,
          last_run_bytes: null,
          last_run_duration_ms: null,
          last_run_error: null,
          next_run_at: null,
          drill_enabled: false,
          drill_cron: null,
          drill_next_run_at: null,
          drill_last_status: "never",
          drill_last_at: null,
          created_at: STAMP,
          modified_at: STAMP,
        },
      ],
    };
    show(<BackupTargetsSection />);
    await screen.findByText("nas");
    const btn = (
      await screen.findAllByTitle(
        "Target is disabled; enable it in Edit to run a backup.",
      )
    )[0] as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });

  it("IPAM Import subnets with no IP space", async () => {
    answers.ipamApi = { listSpaces: async () => [] };
    show(<IPAMPage />);
    const btn = (await screen.findByRole("button", {
      name: "Import subnets",
    })) as HTMLButtonElement;
    await waitFor(() => expect(btn.disabled).toBe(true));
    expect(btn.title).toBe(
      "Create an IP space first; imported subnets need a space to land in.",
    );
  });
});

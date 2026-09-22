import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useStickyLocation } from "@/lib/stickyLocation";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Cpu,
  HardDrive,
  Pause,
  Pencil,
  Phone,
  Play,
  Plus,
  RefreshCw,
  Server,
  Trash2,
  Wifi,
} from "lucide-react";
import {
  dhcpApi,
  dhcpLeaseHistoryApi,
  ipamApi,
  type DHCPPool,
  type DHCPPoolOccupancy,
  type DHCPScope,
  type DHCPServer,
  type DHCPServerGroup,
  type DHCPStaticAssignment,
  type DHCPClientClass,
  type DHCPOptionTemplate,
  type DHCPLease,
  formatApiError,
} from "@/lib/api";
import { useSessionState } from "@/lib/useSessionState";
import { copyToClipboard } from "@/lib/clipboard";
import { cn, zebraBodyCls } from "@/lib/utils";
import { useTableSort, SortableTh } from "@/lib/useTableSort";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { HeaderButton } from "@/components/ui/header-button";
import { Pager } from "@/components/ui/pager";
import { TagFilterChips } from "@/components/TagFilterChips";
import { AskAIButton } from "@/components/copilot/AskAIButton";
import { ServicesUsingButton } from "@/components/ServicesUsingButton";
import { CreateServerGroupModal } from "./CreateServerGroupModal";
import { CreateServerModal } from "./CreateServerModal";
import { ServerDetailModal } from "./ServerDetailModal";
import { PauseServerModal } from "@/components/ui/pause-server-modal";
import { ConfigApplyChip } from "@/components/ConfigApplyChip";
import { DaemonStateChip } from "@/components/DaemonStateChip";
import { CreateScopeModal } from "./CreateScopeModal";
import { CreateClientClassModal } from "./CreateClientClassModal";
import { CreateOptionTemplateModal } from "./CreateOptionTemplateModal";
import { CreateStaticAssignmentModal } from "./CreateStaticAssignmentModal";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";
import { MacBlocksTab } from "./MacBlocksTab";
import { DevicePoliciesTab } from "./DevicePoliciesTab";
import { PhoneProfilesTab } from "./PhoneProfilesTab";
import { DeleteConfirmModal, StatusDot } from "./_shared";
import {
  APPROVAL_QUEUED_MESSAGE,
  CHANGE_REQUEST_QUERY_KEY,
  handleApprovalQueued,
} from "@/lib/approvalQueue";

type Selection =
  | { type: "group"; group: DHCPServerGroup }
  | { type: "server"; group: DHCPServerGroup | null; server: DHCPServer }
  | null;

type Tab =
  | "scopes"
  | "pools"
  | "statics"
  | "classes"
  | "option-templates"
  | "mac-blocks"
  | "leases"
  | "history"
  | "options";

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar
// ─────────────────────────────────────────────────────────────────────────────

function GroupSidebar({
  selection,
  onSelect,
  onCreateGroup,
}: {
  selection: Selection;
  onSelect: (s: Selection) => void;
  onCreateGroup: () => void;
}) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useSessionState<Set<string>>(
    "spatium.dhcp.expandedGroups",
    new Set(),
  );
  const { data: groups = [], isLoading } = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
  });
  const { data: ungrouped = [] } = useQuery({
    queryKey: ["dhcp-servers", "all"],
    queryFn: () => dhcpApi.listServers(),
  });

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="w-72 flex-shrink-0 flex flex-col border-r bg-card">
      <div className="flex items-center justify-between px-4 py-3 border-b">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          DHCP Server Groups
        </span>
        <div className="flex gap-1">
          <button
            className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
            onClick={() => {
              // Force refetch — bare invalidate only marks queries
              // stale, which isn't enough when the user pressed
              // Refresh after external changes (API, another tab).
              qc.refetchQueries({ queryKey: ["dhcp-groups"] });
              qc.refetchQueries({ queryKey: ["dhcp-servers"] });
              qc.refetchQueries({ queryKey: ["dhcp-scopes"] });
            }}
            title="Refresh"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
          <button
            className="flex h-6 w-6 items-center justify-center rounded hover:bg-accent"
            onClick={onCreateGroup}
            title="New group"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto py-1">
        {isLoading && (
          <p className="px-4 py-2 text-xs text-muted-foreground">Loading…</p>
        )}
        {groups.length === 0 && !isLoading && (
          <div className="px-4 pt-6 text-center">
            <Wifi className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-xs text-muted-foreground mb-3">
              No server groups yet.
            </p>
            <button
              className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs mx-auto hover:bg-accent"
              onClick={onCreateGroup}
            >
              <Plus className="h-3 w-3" /> Create Group
            </button>
          </div>
        )}

        {groups.map((g) => {
          const isExpanded = expanded.has(g.id);
          const selected =
            selection?.type === "group" && selection.group.id === g.id;
          const serversInGroup = ungrouped.filter(
            (s) => s.server_group_id === g.id,
          );

          return (
            <div key={g.id}>
              <div
                className={cn(
                  "flex items-center rounded-md mx-1",
                  selected && "bg-primary text-primary-foreground",
                )}
              >
                <button
                  className={cn(
                    "ml-1 flex h-4 w-4 flex-shrink-0 items-center justify-center rounded-sm border text-[10px] font-bold",
                    selected
                      ? "border-primary-foreground/60 bg-primary text-primary-foreground"
                      : "border-border bg-background text-muted-foreground hover:border-primary hover:text-primary",
                  )}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggle(g.id);
                  }}
                  title={isExpanded ? "Collapse" : "Expand"}
                >
                  {isExpanded ? "−" : "+"}
                </button>
                <button
                  className="flex flex-1 items-center gap-2 py-1.5 pl-2 pr-1 min-w-0"
                  onClick={() => {
                    onSelect({ type: "group", group: g });
                    if (!isExpanded) toggle(g.id);
                  }}
                >
                  <Wifi className="h-3.5 w-3.5 flex-shrink-0" />
                  <span className="text-sm font-medium truncate">{g.name}</span>
                  <span className="ml-auto text-xs text-muted-foreground">
                    {serversInGroup.length}
                  </span>
                </button>
              </div>

              {isExpanded && (
                <div className="ml-6 mb-1">
                  {serversInGroup.length === 0 && (
                    <p className="py-1 text-xs text-muted-foreground/70">
                      No servers in this group.
                    </p>
                  )}
                  {serversInGroup.map((s) => {
                    const active =
                      selection?.type === "server" &&
                      selection.server.id === s.id;
                    return (
                      <button
                        key={s.id}
                        onClick={() =>
                          onSelect({ type: "server", group: g, server: s })
                        }
                        className={cn(
                          "flex w-full items-center gap-2 rounded-md px-2 py-1 text-xs",
                          active
                            ? "bg-primary/10 text-primary font-medium"
                            : "hover:bg-accent",
                        )}
                      >
                        <StatusDot status={s.status} />
                        <span className="truncate">{s.name}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {/* Ungrouped servers */}
        {ungrouped.some((s) => !s.server_group_id) && (
          <div className="mt-3 border-t pt-2">
            <p className="px-4 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
              Ungrouped Servers
            </p>
            {ungrouped
              .filter((s) => !s.server_group_id)
              .map((s) => {
                const active =
                  selection?.type === "server" && selection.server.id === s.id;
                return (
                  <button
                    key={s.id}
                    onClick={() =>
                      onSelect({ type: "server", group: null, server: s })
                    }
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-xs mx-1",
                      active
                        ? "bg-primary/10 text-primary font-medium"
                        : "hover:bg-accent",
                    )}
                  >
                    <StatusDot status={s.status} />
                    <span className="truncate">{s.name}</span>
                  </button>
                );
              })}
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Group detail view
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A group is "Kea-managed" when it has at least one Kea member. Those
 * groups host the canonical config tabs (scopes / pools / statics /
 * classes / option templates / MAC blocks / PXE profiles) on the group
 * detail page, since every Kea peer in the group renders the same
 * config bundle.
 *
 * Windows-DHCP groups (or groups with no members yet) keep the legacy
 * per-server layout — Windows operators expect to see scopes on the
 * server they're administering, and group membership for Windows DHCP
 * is typically a one-server group anyway. Per the project model,
 * groups are single-vendor today (Kea OR Windows, not mixed), so the
 * `kea_member_count >= 1` test is sufficient.
 */
function groupIsKeaManaged(group: DHCPServerGroup): boolean {
  return group.kea_member_count > 0;
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

type GroupTab =
  | "servers"
  | "scopes"
  | "pools"
  | "statics"
  | "classes"
  | "option-templates"
  | "mac-blocks"
  | "phone-profiles"
  | "device-policies"
  | "responders"
  | "router-advertisements";

function GroupDetailView({
  group,
  onEdit,
  onDelete,
  onAddServer,
  onSelectServer,
  onEditServer,
  onDeleteServer,
}: {
  group: DHCPServerGroup;
  onEdit: () => void;
  onDelete: () => void;
  onAddServer: () => void;
  onSelectServer: (s: DHCPServer) => void;
  onEditServer: (s: DHCPServer) => void;
  onDeleteServer: (s: DHCPServer) => void;
}) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  // Per-group tab persistence keyed on group id so navigating between
  // groups in the sidebar doesn't bounce the operator off the tab they
  // were just working on.
  const [tab, setTab] = useSessionStateGroupTab(group.id);
  const { enabled: moduleEnabled } = useFeatureModules();
  const raEnabled = moduleEnabled("ipv6.router_advertisements");
  const { data: servers = [], isFetching } = useQuery({
    queryKey: ["dhcp-servers", group.id],
    queryFn: () => dhcpApi.listServers(group.id),
    refetchInterval: 30_000,
  });
  const isKea = groupIsKeaManaged(group);

  // Server list carries ha_state and agent_last_seen, which both
  // change after a group mode edit (hot-standby ↔ load-balancing)
  // once each agent re-renders and its status-get poll fires. Also
  // invalidate dhcp-groups in case the group itself was just edited
  // from another tab / modal and we want the HA mode pill + tuning
  // to be fresh.
  const handleRefresh = () => {
    qc.invalidateQueries({ queryKey: ["dhcp-servers", group.id] });
    qc.invalidateQueries({ queryKey: ["dhcp-groups"] });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-semibold">{group.name}</h1>
              <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
                {group.mode}
              </span>
              <span className="text-xs text-muted-foreground">
                {servers.length} server{servers.length !== 1 ? "s" : ""}
              </span>
            </div>
            {group.description && (
              <p className="mt-1 text-xs text-muted-foreground">
                {group.description}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <AskAIButton
              context={[
                `DHCP server group ${group.name}`,
                `mode: ${group.mode}`,
                `${servers.length} server${servers.length !== 1 ? "s" : ""}`,
                group.description ? `description: ${group.description}` : null,
                `group_id: ${group.id}`,
              ]
                .filter(Boolean)
                .join(", ")}
              tooltip="Ask AI about this DHCP group"
              prompt="Summarise this DHCP group — its servers, scopes, recent leases, and anything notable."
            />
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={handleRefresh}
              title="Refresh server list + HA state"
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              icon={HardDrive}
              onClick={() =>
                navigate(`/dhcp/groups/${encodeURIComponent(group.id)}/pxe`)
              }
              title="PXE / iPXE provisioning profiles for this group"
            >
              PXE Profiles
            </HeaderButton>
            <HeaderButton icon={Pencil} onClick={onEdit}>
              Edit Group
            </HeaderButton>
            <HeaderButton
              variant="destructive"
              icon={Trash2}
              onClick={onDelete}
            >
              Delete Group
            </HeaderButton>
          </div>
        </div>
      </div>

      {isKea && (
        <div className="border-b px-6 bg-card">
          <div className="flex gap-1">
            <TabButton
              active={tab === "servers"}
              onClick={() => setTab("servers")}
            >
              Servers
            </TabButton>
            <TabButton
              active={tab === "scopes"}
              onClick={() => setTab("scopes")}
            >
              Scopes
            </TabButton>
            <TabButton active={tab === "pools"} onClick={() => setTab("pools")}>
              Pools
            </TabButton>
            <TabButton
              active={tab === "statics"}
              onClick={() => setTab("statics")}
            >
              Static Assignments
            </TabButton>
            <TabButton
              active={tab === "classes"}
              onClick={() => setTab("classes")}
            >
              Client Classes
            </TabButton>
            <TabButton
              active={tab === "option-templates"}
              onClick={() => setTab("option-templates")}
            >
              Option Templates
            </TabButton>
            <TabButton
              active={tab === "mac-blocks"}
              onClick={() => setTab("mac-blocks")}
            >
              MAC Blocks
            </TabButton>
            <TabButton
              active={tab === "phone-profiles"}
              onClick={() => setTab("phone-profiles")}
            >
              Phone Profiles
            </TabButton>
            <TabButton
              active={tab === "device-policies"}
              onClick={() => setTab("device-policies")}
            >
              Device Policies
            </TabButton>
            <TabButton
              active={tab === "responders"}
              onClick={() => setTab("responders")}
            >
              Responders
            </TabButton>
            {raEnabled && (
              <TabButton
                active={tab === "router-advertisements"}
                onClick={() => setTab("router-advertisements")}
              >
                Router Adverts
              </TabButton>
            )}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-auto p-6">
        {(!isKea || tab === "servers") && (
          <GroupServersList
            servers={servers}
            onAddServer={onAddServer}
            onSelectServer={onSelectServer}
            onEditServer={onEditServer}
            onDeleteServer={onDeleteServer}
          />
        )}
        {isKea && tab === "scopes" && <ServerScopesTab groupId={group.id} />}
        {isKea && tab === "pools" && (
          <ServerPoolsOrStaticsTab groupId={group.id} kind="pools" />
        )}
        {isKea && tab === "statics" && (
          <ServerPoolsOrStaticsTab groupId={group.id} kind="statics" />
        )}
        {isKea && tab === "classes" && <ClientClassesTab groupId={group.id} />}
        {isKea && tab === "option-templates" && (
          <OptionTemplatesTab groupId={group.id} />
        )}
        {isKea && tab === "mac-blocks" && <MacBlocksTab groupId={group.id} />}
        {isKea && tab === "phone-profiles" && (
          <PhoneProfilesTab groupId={group.id} />
        )}
        {isKea && tab === "device-policies" && (
          <DevicePoliciesTab groupId={group.id} />
        )}
        {isKea && tab === "responders" && <RespondersTab groupId={group.id} />}
        {isKea && raEnabled && tab === "router-advertisements" && (
          <RouterAdvertisementsTab groupId={group.id} />
        )}
      </div>
    </div>
  );
}

// Rogue-DHCP observed responders (#370). Lists DHCP servers the active probe
// saw answering on this group's segments + lets the operator acknowledge a
// known-but-external one (allowlists it so the rogue alert auto-resolves).
function RespondersTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const { data: responders = [], isFetching } = useQuery({
    queryKey: ["dhcp-responders", groupId],
    queryFn: () => dhcpApi.listResponders(groupId),
  });
  const ack = useMutation({
    mutationFn: (id: string) => dhcpApi.acknowledgeResponder(groupId, id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dhcp-responders", groupId] }),
  });
  const badge = (c: string) =>
    c === "rogue"
      ? "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300"
      : c === "acknowledged"
        ? "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300"
        : "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300";
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        DHCP servers seen answering on this group's segments by the active probe
        (enable <code>DHCP_ROGUE_PROBE_ENABLED=1</code> on the agent). Unknown
        responders classify <span className="text-rose-600">rogue</span> and
        fire the Rogue DHCP alert — acknowledge a known-but-external one to
        allowlist it.
      </p>
      <div className="rounded-lg border overflow-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/30 text-xs">
              <th className="px-3 py-2 text-left font-medium">Source IP</th>
              <th className="px-3 py-2 text-left font-medium">Server ID</th>
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">Offered</th>
              <th className="px-3 py-2 text-left font-medium">Class</th>
              <th className="px-3 py-2 text-left font-medium">Last seen</th>
              <th className="px-3 py-2 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {responders.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="p-6 text-center text-sm text-muted-foreground"
                >
                  {isFetching ? "Loading…" : "No responders observed."}
                </td>
              </tr>
            )}
            {responders.map((r) => (
              <tr key={r.id} className="border-b last:border-0">
                <td className="px-3 py-1.5 font-mono text-xs">{r.source_ip}</td>
                <td className="px-3 py-1.5 font-mono text-xs">
                  {r.server_identifier}
                </td>
                <td className="px-3 py-1.5 font-mono text-xs">
                  {r.source_mac || "—"}
                </td>
                <td className="px-3 py-1.5 font-mono text-xs">
                  {r.offered_ip || "—"}
                </td>
                <td className="px-3 py-1.5">
                  <span
                    className={cn(
                      "rounded-full px-2 py-0.5 text-xs",
                      badge(r.classification),
                    )}
                  >
                    {r.classification}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground">
                  {new Date(r.last_seen_at).toLocaleString()}
                </td>
                <td className="px-3 py-1.5 text-right">
                  {r.classification === "rogue" && (
                    <button
                      onClick={() => ack.mutate(r.id)}
                      disabled={ack.isPending}
                      className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
                    >
                      Acknowledge
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// IPv6 Router Advertisements (#524). Shows the radvd config the group's
// RA-enabled scopes render to (M/O flags, lifetimes, RDNSS/DNSSL) plus the
// routers the passive RA sniffer has observed, with an acknowledge action
// that allowlists an expected router so the rogue_ra alert auto-resolves.
function RouterAdvertisementsTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const { data: preview } = useQuery({
    queryKey: ["ra-config", groupId],
    queryFn: () => dhcpApi.raConfigPreview(groupId),
  });
  const { data: routers = [], isFetching } = useQuery({
    queryKey: ["ra-routers", groupId],
    queryFn: () => dhcpApi.listObservedRARouters(groupId),
  });
  const ack = useMutation({
    mutationFn: (id: string) => dhcpApi.acknowledgeRARouter(groupId, id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["ra-routers", groupId] }),
  });
  const badge = (c: string) =>
    c === "rogue"
      ? "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300"
      : c === "acknowledged"
        ? "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300"
        : "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300";
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <h3 className="text-sm font-medium">
          RA configuration ({preview?.scopes.length ?? 0} subnet
          {(preview?.scopes.length ?? 0) === 1 ? "" : "s"})
        </h3>
        <p className="text-xs text-muted-foreground">
          Rendered radvd config for scopes with RA enabled. The DHCP agent runs
          radvd from this when <code>RADVD_MANAGED=1</code>. Turn RA on per
          scope in the scope's IPv6 settings.
        </p>
        {preview && preview.scopes.length > 0 ? (
          <>
            <div className="rounded-lg border overflow-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/30 text-xs">
                    <th className="px-3 py-2 text-left font-medium">Prefix</th>
                    <th className="px-3 py-2 text-left font-medium">Iface</th>
                    <th className="px-3 py-2 text-left font-medium">M / O</th>
                    <th className="px-3 py-2 text-left font-medium">
                      Router life
                    </th>
                    <th className="px-3 py-2 text-left font-medium">RDNSS</th>
                  </tr>
                </thead>
                <tbody className={zebraBodyCls}>
                  {preview.scopes.map((s) => (
                    <tr key={s.scope_id} className="border-b last:border-0">
                      <td className="px-3 py-1.5 font-mono text-xs">
                        {s.subnet_cidr}
                      </td>
                      <td className="px-3 py-1.5 text-xs">
                        {s.interface || "(default)"}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs">
                        {s.managed_flag ? "1" : "0"} /{" "}
                        {s.other_flag ? "1" : "0"}
                      </td>
                      <td className="px-3 py-1.5 text-xs">
                        {s.router_lifetime}s
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs">
                        {s.rdnss.length ? s.rdnss.join(", ") : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground">
                Show rendered radvd.conf
              </summary>
              <pre className="mt-2 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs">
                {preview.radvd_conf}
              </pre>
            </details>
          </>
        ) : (
          <p className="text-xs text-muted-foreground">
            No RA-enabled IPv6 scopes in this group yet.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-medium">Observed routers</h3>
        <p className="text-xs text-muted-foreground">
          IPv6 routers seen advertising on this group's segments by the passive
          RA sniffer (enable <code>DHCP_RA_SNIFFER_ENABLED=1</code> on the
          agent). Unknown routers classify{" "}
          <span className="text-rose-600">rogue</span> and fire the Rogue IPv6
          router alert — acknowledge an expected one to allowlist it.
        </p>
        <div className="rounded-lg border overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/30 text-xs">
                <th className="px-3 py-2 text-left font-medium">Source</th>
                <th className="px-3 py-2 text-left font-medium">MAC</th>
                <th className="px-3 py-2 text-left font-medium">Prefixes</th>
                <th className="px-3 py-2 text-left font-medium">M / O</th>
                <th className="px-3 py-2 text-left font-medium">Class</th>
                <th className="px-3 py-2 text-left font-medium">Last seen</th>
                <th className="px-3 py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {routers.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="p-6 text-center text-sm text-muted-foreground"
                  >
                    {isFetching ? "Loading…" : "No routers observed."}
                  </td>
                </tr>
              )}
              {routers.map((r) => (
                <tr key={r.id} className="border-b last:border-0">
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {r.source_ip}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {r.source_mac || "—"}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {r.prefixes.length ? r.prefixes.join(", ") : "—"}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {r.managed_flag ? "1" : "0"} / {r.other_flag ? "1" : "0"}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "rounded-full px-2 py-0.5 text-xs",
                        badge(r.classification),
                      )}
                    >
                      {r.classification}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-xs text-muted-foreground">
                    {new Date(r.last_seen_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-1.5 text-right">
                    {r.classification === "rogue" && (
                      <button
                        onClick={() => ack.mutate(r.id)}
                        disabled={ack.isPending}
                        className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
                      >
                        Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// Per-group sessionStorage-backed tab state so each group remembers
// the last-active tab independently. A bare `useSessionState` would key
// the same storage slot for every group; we want one per group id.
function useSessionStateGroupTab(
  groupId: string,
): [GroupTab, (next: GroupTab) => void] {
  const key = `dhcp.group.${groupId}.tab`;
  return useSessionState<GroupTab>(key, "servers");
}

// Health pill colour tokens — kept aligned with the DNS ServersTab so
// active / unreachable / syncing / error all render the same green /
// red / blue / red across both pages.
const SERVER_STATUS_PILL_CLS: Record<string, string> = {
  active: "bg-emerald-500/15 text-emerald-600",
  unreachable: "bg-red-500/15 text-red-600",
  syncing: "bg-blue-500/15 text-blue-600",
  error: "bg-red-500/15 text-red-600",
  disabled: "bg-muted text-muted-foreground",
};

const SERVER_STATUS_DOT_CLS: Record<string, string> = {
  active: "bg-emerald-500",
  unreachable: "bg-red-500",
  syncing: "bg-blue-500",
  error: "bg-red-500",
  disabled: "bg-muted-foreground/40",
};

function GroupServersList({
  servers,
  onAddServer,
  onSelectServer,
  onEditServer,
  onDeleteServer,
}: {
  servers: DHCPServer[];
  onAddServer: () => void;
  onSelectServer: (s: DHCPServer) => void;
  onEditServer: (s: DHCPServer) => void;
  onDeleteServer: (s: DHCPServer) => void;
}) {
  const qc = useQueryClient();
  const pauseMutId = useRef<string | null>(null);
  // Pause / resume mutations — shared instance for every row so the
  // ``isPending`` flag can target a single button at a time without
  // multiplying React Query keys. The ``pauseMutId`` ref records which
  // server id is in flight so the buttons stay disabled only on the
  // row being mutated.
  const pauseMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      dhcpApi.pauseServer(id, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-servers"] }),
    onSettled: () => {
      pauseMutId.current = null;
    },
  });
  const resumeMut = useMutation({
    mutationFn: (id: string) => dhcpApi.resumeServer(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-servers"] }),
    onSettled: () => {
      pauseMutId.current = null;
    },
  });
  const [pausePrompt, setPausePrompt] = useState<DHCPServer | null>(null);

  // Health rollup mirrors the DNS ServersTab summary so a fleet-glance
  // matches between the two pages.
  const healthCounts = servers.reduce<Record<string, number>>((acc, s) => {
    acc[s.status] = (acc[s.status] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      {servers.length > 0 && (
        <div className="mb-4 rounded-md border bg-card p-3">
          <div className="flex items-center gap-4 flex-wrap text-xs">
            <span className="font-medium text-muted-foreground uppercase tracking-wider">
              Health
            </span>
            {(["active", "unreachable", "syncing", "error"] as const).map(
              (s) =>
                healthCounts[s] ? (
                  <span key={s} className="flex items-center gap-1.5">
                    <span
                      className={`inline-block h-2 w-2 rounded-full ${SERVER_STATUS_DOT_CLS[s]}`}
                    />
                    {healthCounts[s]} {s}
                  </span>
                ) : null,
            )}
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            DHCP Servers
          </span>
          <p className="text-xs text-muted-foreground mt-0.5">
            Servers can also be auto-registered by Kea agent containers using
            the <code className="font-mono">SPATIUM_AGENT_KEY</code> env var.
          </p>
        </div>
        <button
          className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          onClick={onAddServer}
        >
          <Plus className="h-3 w-3" /> Add Server
        </button>
      </div>

      {servers.length === 0 ? (
        <p className="text-sm text-muted-foreground italic">
          No servers. Add one manually or start a Kea agent container.
        </p>
      ) : (
        <div className="space-y-2">
          {servers.map((s) => {
            // Kea agents send heartbeats; their ``agent_last_seen`` is
            // the right liveness signal. Windows DHCP is polled, so
            // ``last_sync_at`` is meaningful. Fall back to whichever
            // is set.
            const seenAt =
              s.driver === "kea"
                ? (s.agent_last_seen ?? s.last_sync_at)
                : (s.last_sync_at ?? s.agent_last_seen);
            const seenLabel =
              s.driver === "kea"
                ? seenAt
                  ? `seen ${new Date(seenAt).toLocaleTimeString()}`
                  : "never heard from"
                : seenAt
                  ? `synced ${new Date(seenAt).toLocaleTimeString()}`
                  : "never synced";
            const pauseInFlight =
              (pauseMut.isPending || resumeMut.isPending) &&
              pauseMutId.current === s.id;
            return (
              <div
                key={s.id}
                className="flex items-center justify-between rounded-md border bg-card px-3 py-2.5 group cursor-pointer hover:bg-accent/40"
                onClick={() => onSelectServer(s)}
                title="Click to view details"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <Cpu className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`inline-block h-2 w-2 rounded-full ${SERVER_STATUS_DOT_CLS[s.status] ?? "bg-muted"}`}
                        title={`status: ${s.status}`}
                      />
                      <span className="text-sm font-medium">{s.name}</span>
                      <span
                        className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${SERVER_STATUS_PILL_CLS[s.status] ?? "bg-muted text-muted-foreground"}`}
                      >
                        {s.status}
                      </span>
                      <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs">
                        {s.driver}
                      </span>
                      {s.ha_state && (
                        <span
                          className="inline-flex items-center rounded bg-muted/60 px-1.5 py-0.5 text-[11px] text-muted-foreground"
                          title={
                            s.ha_last_heartbeat_at
                              ? `Last HA heartbeat ${new Date(
                                  s.ha_last_heartbeat_at,
                                ).toLocaleString()}`
                              : "No HA heartbeat received yet"
                          }
                        >
                          HA: {s.ha_state}
                        </span>
                      )}
                      {s.maintenance_mode && (
                        <span
                          className="inline-flex items-center rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400"
                          title={
                            s.maintenance_reason
                              ? `Paused: ${s.maintenance_reason}`
                              : "In operator-set maintenance mode"
                          }
                        >
                          Maintenance
                        </span>
                      )}
                      <ConfigApplyChip server={s} />
                      <DaemonStateChip server={s} />
                    </div>
                    <p className="text-xs text-muted-foreground truncate">
                      <span className="font-mono">
                        {s.host}:{s.port}
                      </span>
                      {s.last_seen_ip && (
                        <span
                          className="ml-1.5 font-mono"
                          title="Source IP of the most recent agent heartbeat"
                        >
                          ({s.last_seen_ip})
                        </span>
                      )}
                      {` · ${seenLabel}`}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {s.maintenance_mode ? (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        pauseMutId.current = s.id;
                        resumeMut.mutate(s.id);
                      }}
                      disabled={pauseInFlight}
                      className="inline-flex items-center gap-1 rounded border border-emerald-600/40 bg-emerald-500/10 px-1.5 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-400"
                      title="Resume — exit maintenance mode"
                    >
                      <Play className="h-3 w-3" />
                      {pauseInFlight ? "…" : "Resume"}
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setPausePrompt(s);
                      }}
                      className="inline-flex items-center gap-1 rounded border border-amber-600/40 bg-amber-500/10 px-1.5 py-1 text-[11px] font-medium text-amber-700 hover:bg-amber-500/20 dark:text-amber-400"
                      title="Pause — enter maintenance mode"
                    >
                      <Pause className="h-3 w-3" />
                      Pause
                    </button>
                  )}
                  <button
                    className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                    onClick={(e) => {
                      e.stopPropagation();
                      onEditServer(s);
                    }}
                    title="Edit server"
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                  <button
                    className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-destructive"
                    onClick={(e) => {
                      e.stopPropagation();
                      onDeleteServer(s);
                    }}
                    title="Delete server"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {pausePrompt && (
        <PauseServerModal
          serverName={pausePrompt.name}
          serverKind="DHCP"
          isPending={pauseMut.isPending}
          onConfirm={(reason) => {
            pauseMutId.current = pausePrompt.id;
            pauseMut.mutate(
              { id: pausePrompt.id, reason },
              { onSuccess: () => setPausePrompt(null) },
            );
          }}
          onCancel={() => setPausePrompt(null)}
        />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Server detail view
// ─────────────────────────────────────────────────────────────────────────────

/** Scope delete — always shows the shared ``DeleteConfirmModal`` (so the
 *  user must tick the "I understand" checkbox before the Delete button
 *  enables), but enriches the payload with dependent object counts and a
 *  windows_dhcp-specific warning so the user knows exactly what the
 *  delete will take down with it.
 */
function ScopeDeleteModal({
  scope,
  groupId,
  onConfirm,
  onClose,
  isPending,
  notice,
}: {
  scope: DHCPScope;
  groupId: string;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
  // #62 two-person approval queue "Submitted for approval" message.
  notice?: string | null;
}) {
  const { data: pools = [] } = useQuery({
    queryKey: ["dhcp-pools", scope.id],
    queryFn: () => dhcpApi.listPools(scope.id),
  });
  const { data: statics = [] } = useQuery({
    queryKey: ["dhcp-statics", scope.id],
    queryFn: () => dhcpApi.listStatics(scope.id),
  });
  // The Windows-driver write-through note only applies when the group
  // has at least one Windows DHCP member; pull the group's server list
  // (cheap, already cached by the parent view) and check.
  const { data: groupServers = [] } = useQuery({
    queryKey: ["dhcp-servers", groupId],
    queryFn: () => (groupId ? dhcpApi.listServers(groupId) : []),
    enabled: !!groupId,
  });
  const references: string[] = [];
  if (pools.length)
    references.push(`${pools.length} pool${pools.length === 1 ? "" : "s"}`);
  if (statics.length)
    references.push(
      `${statics.length} reservation${statics.length === 1 ? "" : "s"}`,
    );
  const windowsNote = groupServers.some((s) => s.driver === "windows_dhcp")
    ? " The scope is also removed from the Windows DHCP server via WinRM."
    : "";
  return (
    <DeleteConfirmModal
      title="Delete DHCP Scope"
      description={
        // The old copy — "All its pools and reservations will be removed as
        // well" — described the permanent path, which the UI never takes. The
        // default is a soft-delete: the scope and its children stop being served
        // immediately (agents converge within seconds) but move to Trash
        // together and restore together (#617).
        `Delete scope "${scope.name || scope.id.slice(0, 8)}"? ` +
        "Its pools and reservations go with it — they stop being served straight " +
        "away, and are restorable as a set from Administration → Trash. Any " +
        "dynamic clients (leases) it learned are released too, and their IPAM " +
        "and DNS entries removed." +
        windowsNote
      }
      referencesTitle={
        references.length ? "This scope currently has:" : undefined
      }
      references={references.length ? references : undefined}
      onConfirm={onConfirm}
      onClose={onClose}
      isPending={isPending}
      notice={notice}
    />
  );
}

function ServerScopesTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const [tagFilters, setTagFilters] = useState<string[]>([]);
  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
  });

  // Scopes live on the DHCP server group, not on individual servers — every
  // peer in the group renders the same set. Both the group detail view and
  // the (legacy) Windows-server detail view feed in the same group id.
  const { data: groupScopes = [] } = useQuery({
    queryKey: ["dhcp-scopes-group", groupId, tagFilters],
    queryFn: () =>
      groupId
        ? dhcpApi.listScopesByGroup(
            groupId,
            tagFilters.length > 0 ? { tag: tagFilters } : undefined,
          )
        : Promise.resolve([]),
    enabled: !!groupId,
  });
  const subnetById = new Map(subnets.map((s) => [s.id, s]));
  const allScopes: (DHCPScope & { subnet_network?: string })[] =
    groupScopes.map((sc) => ({
      ...sc,
      subnet_network: subnetById.get(sc.subnet_id)?.network,
    }));

  const [createForSubnet, setCreateForSubnet] = useState<string | null>(null);
  const [editScope, setEditScope] = useState<DHCPScope | null>(null);
  const [delScope, setDelScope] = useState<DHCPScope | null>(null);
  const [delScopeNotice, setDelScopeNotice] = useState<string | null>(null);

  const delMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteScope(id),
    onSuccess: (resp) => {
      // Two-person approval (#62): a covered delete returns 202 with a
      // queued change-request instead of deleting. Surface the message,
      // refresh the approval queue, and leave the scope in place.
      if (handleApprovalQueued(resp)) {
        setDelScopeNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        return;
      }
      qc.invalidateQueries({ queryKey: ["dhcp-scopes-subnet"] });
      qc.invalidateQueries({ queryKey: ["dhcp-scopes-group"] });
      qc.invalidateQueries({ queryKey: ["dhcp-pools"] });
      setDelScope(null);
    },
  });

  return (
    <div className="space-y-3">
      <TagFilterChips
        value={tagFilters}
        onChange={setTagFilters}
        placeholder="Filter scopes by tag — try env or env:prod…"
      />
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {allScopes.length} scope{allScopes.length !== 1 ? "s" : ""} on this
          group.
        </p>
        <div className="flex items-center gap-2">
          <select
            className="rounded-md border bg-background px-2 py-1 text-xs"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) setCreateForSubnet(e.target.value);
              e.target.value = "";
            }}
            title="Pick the IPAM subnet you want this DHCP server to serve leases from."
          >
            <option value="">+ Serve leases on subnet…</option>
            {subnets
              .filter((s) => !allScopes.some((sc) => sc.subnet_id === s.id))
              .map((s) => (
                <option key={s.id} value={s.id}>
                  {s.network}
                  {s.name ? ` — ${s.name}` : ""}
                </option>
              ))}
          </select>
        </div>
      </div>
      <div className="rounded-lg border">
        {allScopes.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            No scopes on this server.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <th className="px-3 py-2 text-left font-medium">Subnet</th>
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">Enabled</th>
                  <th className="px-3 py-2 text-left font-medium">Lease (s)</th>
                  <th className="px-3 py-2 text-left font-medium">DDNS</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {allScopes.map((sc) => (
                  <ContextMenu key={sc.id}>
                    <ContextMenuTrigger asChild>
                      <tr className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono text-xs">
                          {sc.subnet_network ?? "—"}
                        </td>
                        <td className="px-3 py-2">{sc.name}</td>
                        <td className="px-3 py-2">
                          {sc.enabled ? "yes" : "no"}
                        </td>
                        <td className="px-3 py-2 tabular-nums">
                          {sc.lease_time}
                        </td>
                        <td className="px-3 py-2">
                          {sc.ddns_enabled ? "on" : "off"}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <div className="inline-flex items-center justify-end gap-1">
                            <AskAIButton
                              context={[
                                `DHCP scope ${sc.name}`,
                                sc.subnet_network
                                  ? `subnet: ${sc.subnet_network}`
                                  : null,
                                `enabled: ${sc.enabled ? "yes" : "no"}`,
                                `lease time: ${sc.lease_time}s`,
                                `DDNS: ${sc.ddns_enabled ? "on" : "off"}`,
                                `scope_id: ${sc.id}`,
                                sc.subnet_id
                                  ? `subnet_id: ${sc.subnet_id}`
                                  : null,
                              ]
                                .filter(Boolean)
                                .join(", ")}
                              tooltip="Ask AI about this scope"
                              prompt="Summarise this DHCP scope — utilisation, recent leases, any conflicts, anything notable."
                              iconOnly
                              className="px-1.5 py-1"
                            />
                            <ServicesUsingButton
                              kind="dhcp_scope"
                              resourceId={sc.id}
                              label={sc.name}
                              compact
                            />
                            <button
                              onClick={() => setEditScope(sc)}
                              className="rounded p-1 text-muted-foreground hover:text-foreground"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </button>
                            <button
                              onClick={() => setDelScope(sc)}
                              className="rounded p-1 text-muted-foreground hover:text-destructive"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      <ContextMenuLabel>{sc.name}</ContextMenuLabel>
                      <ContextMenuSeparator />
                      <ContextMenuItem onSelect={() => setEditScope(sc)}>
                        Edit Scope…
                      </ContextMenuItem>
                      <ContextMenuItem
                        destructive
                        onSelect={() => setDelScope(sc)}
                      >
                        Delete Scope…
                      </ContextMenuItem>
                      <ContextMenuSeparator />
                      <ContextMenuItem
                        onSelect={() => copyToClipboard(sc.name)}
                      >
                        Copy Scope Name
                      </ContextMenuItem>
                      {sc.subnet_network && (
                        <ContextMenuItem
                          onSelect={() => copyToClipboard(sc.subnet_network!)}
                        >
                          Copy Subnet CIDR
                        </ContextMenuItem>
                      )}
                    </ContextMenuContent>
                  </ContextMenu>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {createForSubnet && (
        <CreateScopeModal
          subnetId={createForSubnet}
          defaultGroupId={groupId || undefined}
          onClose={() => setCreateForSubnet(null)}
        />
      )}
      {editScope && (
        <CreateScopeModal
          scope={editScope}
          onClose={() => setEditScope(null)}
        />
      )}
      {delScope && (
        <ScopeDeleteModal
          scope={delScope}
          groupId={groupId}
          onConfirm={() => delMut.mutate(delScope.id)}
          onClose={() => {
            setDelScope(null);
            setDelScopeNotice(null);
            delMut.reset();
          }}
          isPending={delMut.isPending}
          notice={delScopeNotice}
        />
      )}
    </div>
  );
}

/**
 * Live pool occupancy (#913).
 *
 * `assigned` unions active leases with in-pool static reservations, so a
 * reserved-but-offline address reads as taken — counting leases alone
 * under-reports exhaustion, which is the failure that sends a technician
 * looking in the wrong place.
 *
 * Answered for dynamic pools only, matching the alert evaluator and the
 * copilot tool. Each other type would produce a misleading number: a pd
 * pool's start/end are placeholders for a delegated prefix rather than a
 * range, an excluded range is never offered to a client at all, and a
 * reserved range is *supposed* to fill up — colouring that red would
 * flag a correctly-configured pool as exhausted.
 */
function PoolOccupancyCell({
  occ,
  poolType,
}: {
  occ?: DHCPPoolOccupancy;
  poolType: string;
}) {
  if (poolType !== "dynamic") {
    return <span className="text-xs text-muted-foreground/60">n/a</span>;
  }
  if (!occ) {
    return <span className="text-xs text-muted-foreground/40">—</span>;
  }
  const tone =
    occ.percent >= 90
      ? "bg-rose-500"
      : occ.percent >= 75
        ? "bg-amber-500"
        : "bg-emerald-500";
  return (
    <div
      className="flex min-w-[9rem] items-center gap-2"
      title={`${occ.assigned} of ${occ.total} addresses in use, ${occ.free} free`}
    >
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full ${tone}`}
          style={{ width: `${Math.min(100, occ.percent)}%` }}
        />
      </div>
      <span className="font-mono text-xs tabular-nums text-muted-foreground">
        {occ.assigned}/{occ.total}
      </span>
      <span className="font-mono text-xs tabular-nums">
        {occ.percent.toFixed(0)}%
      </span>
    </div>
  );
}

function ServerPoolsOrStaticsTab({
  groupId,
  kind,
}: {
  groupId: string;
  kind: "pools" | "statics";
}) {
  // Scopes belong to the group — pull them once and walk into each scope
  // for its pool / static rows. Empty when the group has no scopes yet.
  const { data: groupScopes = [] } = useQuery({
    queryKey: ["dhcp-scopes-group", groupId],
    queryFn: () =>
      groupId ? dhcpApi.listScopesByGroup(groupId) : Promise.resolve([]),
    enabled: !!groupId,
  });
  const allScopes = groupScopes;

  const nestedQueries = useQueries({
    queries: allScopes.map((sc) => ({
      queryKey: [kind === "pools" ? "dhcp-pools" : "dhcp-statics", sc.id],
      queryFn: () =>
        kind === "pools"
          ? dhcpApi.listPools(sc.id)
          : dhcpApi.listStatics(sc.id),
    })),
  });

  // Live occupancy per pool (#913). One call per scope rather than one
  // per pool — the scope endpoint batches the lease + reservation lookup,
  // which is the reason it exists. Only fetched on the pools tab.
  const occupancyQueries = useQueries({
    queries: allScopes.map((sc) => ({
      queryKey: ["dhcp-pool-occupancy", sc.id],
      queryFn: () => dhcpApi.scopePoolOccupancy(sc.id),
      enabled: kind === "pools",
      staleTime: 15_000,
    })),
  });
  const occupancyByPool = new Map<string, DHCPPoolOccupancy>();
  for (const q of occupancyQueries) {
    for (const row of q.data ?? []) occupancyByPool.set(row.pool_id, row);
  }

  const rows: Array<{
    scope: DHCPScope;
    item: DHCPPool | DHCPStaticAssignment;
  }> = nestedQueries.flatMap((q, i) =>
    (q.data ?? []).map((item) => ({ scope: allScopes[i]!, item })),
  );

  type PoolRow = { scope: DHCPScope; item: DHCPPool };
  type StaticRow = { scope: DHCPScope; item: DHCPStaticAssignment };

  const ipToInt = (s: string | null | undefined) => {
    if (!s) return -1;
    const parts = s.split(".").map(Number);
    if (parts.length !== 4 || parts.some(Number.isNaN)) return s;
    return (
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
    );
  };

  // Both sort hooks run on every render (hooks can't be conditional), but
  // `rows` is homogeneous per `kind` — when kind=="pools", rows are all
  // DHCPPool, so the static-row sort sees undefined fields. Guards below
  // keep the comparator null-safe either way.
  const {
    sorted: poolRows,
    sort: poolSort,
    toggle: togglePoolSort,
  } = useTableSort<PoolRow, "scope" | "name" | "start" | "end" | "type">(
    rows as PoolRow[],
    { key: "start", dir: "asc" },
    (row, key) => {
      if (key === "scope") return row.scope?.name ?? "";
      if (key === "name") return row.item?.name ?? "";
      if (key === "start") return ipToInt(row.item?.start_ip);
      if (key === "end") return ipToInt(row.item?.end_ip);
      if (key === "type") return row.item?.pool_type ?? "";
      return "";
    },
  );

  const {
    sorted: staticRows,
    sort: staticSort,
    toggle: toggleStaticSort,
  } = useTableSort<StaticRow, "scope" | "mac" | "ip" | "hostname">(
    rows as StaticRow[],
    { key: "ip", dir: "asc" },
    (row, key) => {
      if (key === "scope") return row.scope?.name ?? "";
      if (key === "mac") return row.item?.mac_address ?? "";
      if (key === "ip") return ipToInt(row.item?.ip_address);
      if (key === "hostname") return row.item?.hostname ?? "";
      return "";
    },
  );

  // Static reservations are created/edited here (issue #472). Creation is
  // group-centric — the operator picks which scope the reservation lands in.
  // Backend create/update/delete are superadmin-gated, so gate the UI too.
  const qc = useQueryClient();
  const { isSuperadmin } = usePermissions();
  const [showCreate, setShowCreate] = useState(false);
  const [createScopeId, setCreateScopeId] = useState("");
  const [editStatic, setEditStatic] = useState<StaticRow | null>(null);
  const [delStatic, setDelStatic] = useState<StaticRow | null>(null);
  const createScope =
    allScopes.find((s) => s.id === createScopeId) ?? allScopes[0] ?? null;
  const delMut = useMutation({
    mutationFn: (row: StaticRow) =>
      dhcpApi.deleteStatic(row.scope.id, row.item.id),
    onSuccess: (_r, row) => {
      qc.invalidateQueries({ queryKey: ["dhcp-statics", row.scope.id] });
      // Delete detaches the linked IPAM row + triggers DNS sync server-side,
      // so refresh the same IPAM/DNS keys the create/edit modal invalidates.
      qc.invalidateQueries({ queryKey: ["addresses", row.scope.subnet_id] });
      qc.invalidateQueries({
        queryKey: ["subnet-dns-sync", row.scope.subnet_id],
      });
      setDelStatic(null);
    },
  });
  const canManageStatics = kind === "statics" && isSuperadmin;

  return (
    <div className="space-y-3">
      {canManageStatics && allScopes.length > 0 && (
        <div className="flex items-center justify-end gap-2">
          {allScopes.length > 1 && (
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
              Add to scope
              <select
                className="rounded-md border bg-background px-2 py-1 text-xs"
                value={createScope?.id ?? ""}
                onChange={(e) => setCreateScopeId(e.target.value)}
              >
                {allScopes.map((sc) => (
                  <option key={sc.id} value={sc.id}>
                    {sc.name || `Scope ${sc.id.slice(0, 8)}`}
                  </option>
                ))}
              </select>
            </label>
          )}
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3 w-3" /> New static assignment
          </button>
        </div>
      )}
      <div className="rounded-lg border">
        {rows.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            {kind === "pools"
              ? "No pools yet."
              : allScopes.length === 0
                ? "No DHCP scopes in this group yet — create a scope first, then add reservations here."
                : "No static assignments yet."}
          </p>
        ) : kind === "pools" ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <SortableTh
                    sortKey="scope"
                    sort={poolSort}
                    onSort={togglePoolSort}
                    className="px-3 py-2"
                  >
                    Scope
                  </SortableTh>
                  <SortableTh
                    sortKey="name"
                    sort={poolSort}
                    onSort={togglePoolSort}
                    className="px-3 py-2"
                  >
                    Name
                  </SortableTh>
                  <SortableTh
                    sortKey="start"
                    sort={poolSort}
                    onSort={togglePoolSort}
                    className="px-3 py-2"
                  >
                    Start
                  </SortableTh>
                  <SortableTh
                    sortKey="end"
                    sort={poolSort}
                    onSort={togglePoolSort}
                    className="px-3 py-2"
                  >
                    End
                  </SortableTh>
                  <SortableTh
                    sortKey="type"
                    sort={poolSort}
                    onSort={togglePoolSort}
                    className="px-3 py-2"
                  >
                    Type
                  </SortableTh>
                  <th className="px-3 py-2 text-left font-medium">Occupancy</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {poolRows.map(({ scope, item }) => {
                  const p = item;
                  return (
                    <tr key={p.id} className="border-b last:border-0">
                      <td className="px-3 py-2 text-xs">{scope.name}</td>
                      <td className="px-3 py-2">{p.name || "—"}</td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {p.start_ip}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {p.end_ip}
                      </td>
                      <td className="px-3 py-2">
                        <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
                          {p.pool_type}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <PoolOccupancyCell
                          occ={occupancyByPool.get(p.id)}
                          poolType={p.pool_type}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <SortableTh
                    sortKey="scope"
                    sort={staticSort}
                    onSort={toggleStaticSort}
                    className="px-3 py-2"
                  >
                    Scope
                  </SortableTh>
                  <SortableTh
                    sortKey="mac"
                    sort={staticSort}
                    onSort={toggleStaticSort}
                    className="px-3 py-2"
                  >
                    MAC
                  </SortableTh>
                  <SortableTh
                    sortKey="ip"
                    sort={staticSort}
                    onSort={toggleStaticSort}
                    className="px-3 py-2"
                  >
                    IP
                  </SortableTh>
                  <SortableTh
                    sortKey="hostname"
                    sort={staticSort}
                    onSort={toggleStaticSort}
                    className="px-3 py-2"
                  >
                    Hostname
                  </SortableTh>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {staticRows.map(({ scope, item }) => {
                  const s = item;
                  return (
                    <ContextMenu key={s.id}>
                      <ContextMenuTrigger asChild>
                        <tr className="border-b last:border-0">
                          <td className="px-3 py-2 text-xs">{scope.name}</td>
                          <td className="px-3 py-2 font-mono text-xs">
                            {s.mac_address}
                          </td>
                          <td className="px-3 py-2 font-mono text-xs">
                            {s.ip_address}
                          </td>
                          <td className="px-3 py-2">{s.hostname || "—"}</td>
                        </tr>
                      </ContextMenuTrigger>
                      <ContextMenuContent>
                        <ContextMenuLabel>{s.ip_address}</ContextMenuLabel>
                        <ContextMenuSeparator />
                        <ContextMenuItem
                          onSelect={() => copyToClipboard(s.ip_address)}
                        >
                          Copy IP
                        </ContextMenuItem>
                        <ContextMenuItem
                          onSelect={() => copyToClipboard(s.mac_address)}
                        >
                          Copy MAC
                        </ContextMenuItem>
                        {s.hostname && (
                          <ContextMenuItem
                            onSelect={() => copyToClipboard(s.hostname!)}
                          >
                            Copy Hostname
                          </ContextMenuItem>
                        )}
                        {canManageStatics && (
                          <>
                            <ContextMenuSeparator />
                            <ContextMenuItem
                              onSelect={() => setEditStatic({ scope, item: s })}
                            >
                              Edit…
                            </ContextMenuItem>
                            <ContextMenuItem
                              onSelect={() => setDelStatic({ scope, item: s })}
                            >
                              Delete…
                            </ContextMenuItem>
                          </>
                        )}
                      </ContextMenuContent>
                    </ContextMenu>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {showCreate && createScope && (
        <CreateStaticAssignmentModal
          scope={createScope}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editStatic && (
        <CreateStaticAssignmentModal
          scope={editStatic.scope}
          staticAssignment={editStatic.item}
          onClose={() => setEditStatic(null)}
        />
      )}
      {delStatic && (
        <DeleteConfirmModal
          title="Delete Static Assignment"
          description={`Delete reservation ${delStatic.item.ip_address} (${delStatic.item.mac_address})?`}
          onConfirm={() => delMut.mutate(delStatic)}
          onClose={() => setDelStatic(null)}
          isPending={delMut.isPending}
          error={
            delMut.isError
              ? formatApiError(delMut.error, "Delete failed")
              : null
          }
        />
      )}
    </div>
  );
}

function ClientClassesTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const { data: classes = [] } = useQuery({
    queryKey: ["dhcp-client-classes", groupId],
    queryFn: () =>
      groupId ? dhcpApi.listClientClasses(groupId) : Promise.resolve([]),
    enabled: !!groupId,
  });
  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<DHCPClientClass | null>(null);
  const [del, setDel] = useState<DHCPClientClass | null>(null);
  const delMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteClientClass(groupId, id),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["dhcp-client-classes", groupId],
      });
      setDel(null);
    },
  });

  if (!groupId) {
    return (
      <p className="p-6 text-center text-sm text-muted-foreground">
        Client classes are configured on the server group — attach this server
        to a group first.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3 w-3" /> New Client Class
        </button>
      </div>
      <div className="rounded-lg border">
        {classes.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            No client classes defined.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">
                    Description
                  </th>
                  <th className="px-3 py-2 text-left font-medium">Match</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {classes.map((c) => (
                  <tr key={c.id} className="border-b last:border-0">
                    <td className="px-3 py-2 font-medium">{c.name}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {c.description}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs truncate max-w-md">
                      {c.match_expression}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => setEdit(c)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDel(c)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <CreateClientClassModal
          groupId={groupId}
          onClose={() => setShowCreate(false)}
        />
      )}
      {edit && (
        <CreateClientClassModal
          klass={edit}
          groupId={groupId}
          onClose={() => setEdit(null)}
        />
      )}
      {del && (
        <DeleteConfirmModal
          title="Delete Client Class"
          description={`Delete class "${del.name}"?`}
          onConfirm={() => delMut.mutate(del.id)}
          onClose={() => setDel(null)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

function OptionTemplatesTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const { data: templates = [] } = useQuery({
    queryKey: ["dhcp-option-templates", groupId],
    queryFn: () =>
      groupId ? dhcpApi.listOptionTemplates(groupId) : Promise.resolve([]),
    enabled: !!groupId,
  });
  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<DHCPOptionTemplate | null>(null);
  const [del, setDel] = useState<DHCPOptionTemplate | null>(null);
  const delMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteOptionTemplate(groupId, id),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["dhcp-option-templates", groupId],
      });
      setDel(null);
    },
  });

  if (!groupId) {
    return (
      <p className="p-6 text-center text-sm text-muted-foreground">
        Option templates are configured on the server group — attach this server
        to a group first.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Named bundles of DHCP options that can be applied to a scope in one
          click. Apply is a stamp — later edits to a template do not propagate
          back to scopes that already used it.
        </p>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3 w-3" /> New Template
        </button>
      </div>
      <div className="rounded-lg border">
        {templates.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            No option templates defined.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">
                    Description
                  </th>
                  <th className="px-3 py-2 text-left font-medium">Family</th>
                  <th className="px-3 py-2 text-left font-medium">Options</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {templates.map((t) => (
                  <tr key={t.id} className="border-b last:border-0">
                    <td className="px-3 py-2 font-medium">{t.name}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {t.description}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {t.address_family}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                      {Object.keys(t.options ?? {})
                        .sort()
                        .slice(0, 5)
                        .join(", ")}
                      {Object.keys(t.options ?? {}).length > 5 && " …"}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => setEdit(t)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDel(t)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <CreateOptionTemplateModal
          groupId={groupId}
          onClose={() => setShowCreate(false)}
        />
      )}
      {edit && (
        <CreateOptionTemplateModal
          template={edit}
          groupId={groupId}
          onClose={() => setEdit(null)}
        />
      )}
      {del && (
        <DeleteConfirmModal
          title="Delete Option Template"
          description={`Delete template "${del.name}"? Scopes that already had it applied keep their options.`}
          onConfirm={() => delMut.mutate(del.id)}
          onClose={() => setDel(null)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

function LeasesTab({ server }: { server: DHCPServer }) {
  const [state, setState] = useState<string>("");
  const [subnetId, setSubnetId] = useState<string>("");
  const [deviceClass, setDeviceClass] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [page, setPage] = useState(1);
  const pageSize = 100;

  const qc = useQueryClient();
  const { isSuperadmin } = usePermissions();
  // Manual single-lease delete (#478). Backend is SuperAdmin-gated, so only
  // offer it to superadmins. A still-live lease may be re-learned on the next
  // poll — this is for expired/stray leases; scope deletion handles the rest.
  const [del, setDel] = useState<DHCPLease | null>(null);
  const delMut = useMutation({
    mutationFn: (leaseId: string) => dhcpApi.deleteLease(server.id, leaseId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-leases", server.id] });
      setDel(null);
    },
  });

  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
  });

  // Server-side pagination + search (#455). `search` (ip / mac / hostname) and
  // `state` filter on the server so a busy server's older leases are reachable
  // past page 1; subnet + device-class stay client-side refinements over the
  // current page.
  const params = useMemo(() => {
    const p: {
      page: number;
      page_size: number;
      search?: string;
      state?: string;
    } = { page, page_size: pageSize };
    if (search.trim()) p.search = search.trim();
    if (state) p.state = state;
    return p;
  }, [page, search, state]);

  const { data, isFetching, refetch } = useQuery({
    queryKey: ["dhcp-leases", server.id, params],
    queryFn: () => dhcpApi.getLeases(server.id, params),
  });

  const allLeases = data?.items ?? [];
  const total = data?.total ?? 0;
  // Distinct fingerbank device classes on the current page — drives the
  // device-class refinement (#373), client-side over the visible page.
  const deviceClasses = Array.from(
    new Set(
      allLeases.map((l) => l.device_class).filter((c): c is string => !!c),
    ),
  ).sort();
  const leases = allLeases.filter((l) => {
    if (subnetId && l.scope_id !== subnetId) return false;
    if (deviceClass && l.device_class !== deviceClass) return false;
    return true;
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <input
          className="rounded-md border bg-background px-2 py-1 text-xs"
          placeholder="Search ip / mac / hostname…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
        <select
          className="rounded-md border bg-background px-2 py-1 text-xs"
          value={state}
          onChange={(e) => {
            setState(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All states</option>
          <option value="active">Active</option>
          <option value="expired">Expired</option>
          <option value="released">Released</option>
          <option value="declined">Declined</option>
        </select>
        <select
          className="rounded-md border bg-background px-2 py-1 text-xs"
          value={subnetId}
          onChange={(e) => setSubnetId(e.target.value)}
        >
          <option value="">All subnets</option>
          {subnets.map((s) => (
            <option key={s.id} value={s.id}>
              {s.network}
            </option>
          ))}
        </select>
        {deviceClasses.length > 0 && (
          <select
            className="rounded-md border bg-background px-2 py-1 text-xs"
            value={deviceClass}
            onChange={(e) => setDeviceClass(e.target.value)}
            title="Filter by fingerbank device class"
          >
            <option value="">All device classes</option>
            {deviceClasses.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        )}
        <div className="ml-auto flex items-center gap-3">
          <Pager
            page={page}
            total={total}
            pageSize={pageSize}
            onChange={setPage}
          />
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
            disabled={isFetching}
          >
            <RefreshCw
              className={cn("h-3 w-3", isFetching && "animate-spin")}
            />
            Refresh
          </button>
        </div>
      </div>
      <div className="rounded-lg border overflow-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/30 text-xs">
              <th className="px-3 py-2 text-left font-medium">IP</th>
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">Hostname</th>
              <th className="px-3 py-2 text-left font-medium">Device</th>
              <th className="px-3 py-2 text-left font-medium">State</th>
              <th className="px-3 py-2 text-left font-medium">Expires</th>
              <th className="px-3 py-2 text-left font-medium">Last Seen</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {leases.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="p-6 text-center text-sm text-muted-foreground"
                >
                  {isFetching ? "Loading…" : "No leases."}
                </td>
              </tr>
            )}
            {leases.map((l: DHCPLease) => (
              <ContextMenu key={l.id}>
                <ContextMenuTrigger asChild>
                  <tr className="border-b last:border-0">
                    <td className="px-3 py-1.5 font-mono text-xs">
                      {l.ip_address}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-xs">
                      {l.mac_address}
                      {l.is_voip_phone && (
                        <span
                          title={
                            l.vendor ? `VoIP phone — ${l.vendor}` : "VoIP phone"
                          }
                          className="inline-flex"
                        >
                          <Phone
                            className="ml-1 inline h-3 w-3 align-text-bottom text-sky-600 dark:text-sky-400"
                            aria-label="VoIP phone"
                          />
                        </span>
                      )}
                      {l.vendor && (
                        <span className="ml-1 font-sans text-[11px] text-muted-foreground">
                          ({l.vendor})
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-1.5">{l.hostname || "—"}</td>
                    <td className="px-3 py-1.5 text-xs">
                      {l.device_class ? (
                        <span
                          title={
                            [
                              l.device_name,
                              l.device_manufacturer,
                              l.fingerbank_score != null
                                ? `score ${l.fingerbank_score}`
                                : null,
                            ]
                              .filter(Boolean)
                              .join(" · ") || undefined
                          }
                        >
                          {l.device_class}
                          {l.device_name && (
                            <span className="block text-[11px] text-muted-foreground">
                              {l.device_name}
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-3 py-1.5">
                      <span
                        className={cn(
                          "rounded-full px-2 py-0.5 text-xs",
                          l.state === "active"
                            ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                            : "bg-muted text-muted-foreground",
                        )}
                      >
                        {l.state}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-xs text-muted-foreground">
                      {l.expires_at
                        ? new Date(l.expires_at).toLocaleString()
                        : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-xs text-muted-foreground">
                      {l.last_seen_at
                        ? new Date(l.last_seen_at).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                </ContextMenuTrigger>
                <ContextMenuContent>
                  <ContextMenuLabel>{l.ip_address}</ContextMenuLabel>
                  <ContextMenuSeparator />
                  <ContextMenuItem
                    onSelect={() => copyToClipboard(l.ip_address)}
                  >
                    Copy IP
                  </ContextMenuItem>
                  <ContextMenuItem
                    onSelect={() => copyToClipboard(l.mac_address)}
                  >
                    Copy MAC
                  </ContextMenuItem>
                  {l.hostname && (
                    <ContextMenuItem
                      onSelect={() => copyToClipboard(l.hostname!)}
                    >
                      Copy Hostname
                    </ContextMenuItem>
                  )}
                  {isSuperadmin && (
                    <>
                      <ContextMenuSeparator />
                      <ContextMenuItem
                        className="text-destructive"
                        onSelect={() => setDel(l)}
                      >
                        Delete lease
                      </ContextMenuItem>
                    </>
                  )}
                </ContextMenuContent>
              </ContextMenu>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          {total.toLocaleString()} lease{total === 1 ? "" : "s"}
          {(subnetId || deviceClass) && " (page filtered)"}
          {isFetching && " · loading…"}
        </span>
        <Pager
          page={page}
          total={total}
          pageSize={pageSize}
          onChange={setPage}
        />
      </div>
      {del && (
        <DeleteConfirmModal
          title="Delete Lease"
          description={
            `Delete the lease for ${del.ip_address} (${del.mac_address})? ` +
            "This removes the lease and its IPAM mirror. A still-active lease " +
            "may be re-learned on the next poll — this is for stray or expired " +
            "leases; deleting the scope clears its leases automatically."
          }
          onConfirm={() => delMut.mutate(del.id)}
          onClose={() => setDel(null)}
          isPending={delMut.isPending}
          error={
            delMut.isError
              ? "Delete failed — check your permissions or refresh the list."
              : null
          }
        />
      )}
    </div>
  );
}

// Default to "last 7 days" for the History tab — operators usually
// want recent context, not the whole 90-day window. Returns an ISO
// timestamp suitable for the ``since`` query param.
function defaultHistorySince(): string {
  const d = new Date();
  d.setDate(d.getDate() - 7);
  return d.toISOString();
}

function LeaseHistoryTab({ server }: { server: DHCPServer }) {
  const [state, setState] = useState<string>("");
  const [mac, setMac] = useState<string>("");
  const [ip, setIp] = useState<string>("");
  const [hostname, setHostname] = useState<string>("");
  const [since, setSince] = useState<string>(defaultHistorySince());
  const [page, setPage] = useState<number>(1);
  const perPage = 50;

  const params = useMemo(
    () => ({
      lease_state: state || undefined,
      mac: mac || undefined,
      ip: ip || undefined,
      hostname: hostname || undefined,
      since: since || undefined,
      page,
      per_page: perPage,
    }),
    [state, mac, ip, hostname, since, page],
  );

  const { data, isFetching, refetch } = useQuery({
    queryKey: ["dhcp-lease-history", server.id, params],
    queryFn: () => dhcpLeaseHistoryApi.list(server.id, params),
    placeholderData: (prev) => prev,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <select
          className="rounded-md border bg-background px-2 py-1 text-xs"
          value={state}
          onChange={(e) => {
            setState(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All states</option>
          <option value="expired">Expired</option>
          <option value="released">Released</option>
          <option value="removed">Removed</option>
          <option value="superseded">Superseded</option>
        </select>
        <input
          className="rounded-md border bg-background px-2 py-1 text-xs"
          placeholder="MAC contains…"
          value={mac}
          onChange={(e) => {
            setMac(e.target.value);
            setPage(1);
          }}
        />
        <input
          className="rounded-md border bg-background px-2 py-1 text-xs"
          placeholder="IP / CIDR"
          value={ip}
          onChange={(e) => {
            setIp(e.target.value);
            setPage(1);
          }}
        />
        <input
          className="rounded-md border bg-background px-2 py-1 text-xs"
          placeholder="Hostname contains…"
          value={hostname}
          onChange={(e) => {
            setHostname(e.target.value);
            setPage(1);
          }}
        />
        <input
          type="datetime-local"
          className="rounded-md border bg-background px-2 py-1 text-xs"
          // Slice off seconds + Z to satisfy the input control's local
          // datetime format. Round-trip back to ISO Z on change.
          value={since ? since.slice(0, 16) : ""}
          onChange={(e) => {
            setSince(
              e.target.value ? new Date(e.target.value).toISOString() : "",
            );
            setPage(1);
          }}
          title="Show entries with expired_at on or after this time"
        />
        <button
          onClick={() => refetch()}
          className="ml-auto flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          disabled={isFetching}
        >
          <RefreshCw className={cn("h-3 w-3", isFetching && "animate-spin")} />
          Refresh
        </button>
      </div>
      <div className="rounded-lg border overflow-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/30 text-xs">
              <th className="px-3 py-2 text-left font-medium">IP</th>
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">Hostname</th>
              <th className="px-3 py-2 text-left font-medium">State</th>
              <th className="px-3 py-2 text-left font-medium">Started</th>
              <th className="px-3 py-2 text-left font-medium">Ended at</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {items.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="p-6 text-center text-sm text-muted-foreground"
                >
                  {isFetching ? "Loading…" : "No history entries match."}
                </td>
              </tr>
            )}
            {items.map((row) => (
              <tr key={row.id} className="border-b last:border-0">
                <td className="px-3 py-1.5 font-mono text-xs">
                  {row.ip_address}
                </td>
                <td className="px-3 py-1.5 font-mono text-xs">
                  {row.mac_address}
                </td>
                <td className="px-3 py-1.5">{row.hostname || "—"}</td>
                <td className="px-3 py-1.5">
                  <span
                    className={cn(
                      "rounded-full px-2 py-0.5 text-xs",
                      row.lease_state === "expired"
                        ? "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400"
                        : row.lease_state === "removed"
                          ? "bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-400"
                          : row.lease_state === "superseded"
                            ? "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-400"
                            : "bg-muted text-muted-foreground",
                    )}
                  >
                    {row.lease_state}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground">
                  {row.started_at
                    ? new Date(row.started_at).toLocaleString()
                    : "—"}
                </td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground">
                  {new Date(row.expired_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {total > 0 && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>
            {total} entr{total === 1 ? "y" : "ies"} • page {page} / {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              className="rounded-md border px-2 py-1 hover:bg-accent disabled:opacity-50"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
            >
              Prev
            </button>
            <button
              className="rounded-md border px-2 py-1 hover:bg-accent disabled:opacity-50"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ServerDetailView({
  server,
  group,
  onEdit,
  onDelete,
  onSelectGroup,
}: {
  server: DHCPServer;
  group: DHCPServerGroup | null;
  onEdit: () => void;
  onDelete: () => void;
  onSelectGroup?: (group: DHCPServerGroup) => void;
}) {
  const qc = useQueryClient();
  // For Kea servers attached to a Kea-managed group, scopes / pools /
  // statics / classes / option templates / MAC blocks all live on the
  // group, not on this individual peer — we hide those tabs here and
  // surface a banner pointing the operator to the group page. Windows
  // DHCP servers keep every tab on the per-server page exactly as
  // before; that's the model their operators expect.
  const groupOwnsConfig =
    server.driver === "kea" && group !== null && groupIsKeaManaged(group);
  const [tab, setTab] = useState<Tab>(groupOwnsConfig ? "leases" : "scopes");
  const [syncBanner, setSyncBanner] = useState<string | null>(null);
  // 409 from a FortiGate sync: an operator-managed DHCP object already exists
  // on the interface. Holds the detail so we can offer an adopt-and-retry.
  const [adoptConflict, setAdoptConflict] = useState<string | null>(null);
  const syncMut = useMutation({
    mutationFn: (adoptExisting: boolean = false) =>
      dhcpApi.syncServer(server.id, adoptExisting),
    onSuccess: () => {
      setSyncBanner(null);
      setAdoptConflict(null);
      qc.invalidateQueries({ queryKey: ["dhcp-servers"] });
    },
    onError: (e) => {
      const err = e as {
        response?: { status?: number; data?: { detail?: string } };
      };
      const detail = err?.response?.data?.detail;
      if (err?.response?.status === 409) {
        setAdoptConflict(
          detail ?? "A DHCP server already exists on the interface.",
        );
      } else {
        setSyncBanner(detail ?? "Force sync failed");
      }
    },
  });
  const leaseSyncMut = useMutation({
    mutationFn: () => dhcpApi.syncLeasesNow(server.id),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["dhcp-servers"] });
      qc.invalidateQueries({ queryKey: ["dhcp-leases", server.id] });
      // Lease sync mirrors leases into IPAM as status=dhcp rows; broad
      // invalidation refreshes any ["addresses", subnetId] subquery.
      qc.invalidateQueries({ queryKey: ["addresses"] });
      // Also invalidate subnet-level scope queries so the DHCP topology
      // views refresh once scopes / pools / statics get imported.
      qc.invalidateQueries({ queryKey: ["dhcp-scopes"] });
      const parts: string[] = [];
      // Agent-based no-op note (Kea) takes the whole banner — there are no
      // lease counters to report on that path.
      if (result.note) {
        setSyncBanner(result.note);
        return;
      }
      // Topology line first — only shown when the driver imports scopes.
      if (
        result.scopes_imported ||
        result.scopes_refreshed ||
        result.scopes_skipped_no_subnet
      ) {
        const scopeBits: string[] = [];
        if (result.scopes_imported)
          scopeBits.push(`${result.scopes_imported} scopes imported`);
        if (result.scopes_refreshed)
          scopeBits.push(`${result.scopes_refreshed} refreshed`);
        if (result.scopes_skipped_no_subnet)
          scopeBits.push(
            `${result.scopes_skipped_no_subnet} skipped (no matching IPAM subnet)`,
          );
        // Counts are changes, not totals: the scope reconciler diff-merges, so
        // an unchanged pool / reservation is not touched and not counted.
        if (result.pools_synced)
          scopeBits.push(`${result.pools_synced} pools changed`);
        if (result.pools_removed)
          scopeBits.push(`${result.pools_removed} pools removed`);
        if (result.statics_synced)
          scopeBits.push(`${result.statics_synced} reservations changed`);
        if (result.statics_removed)
          scopeBits.push(`${result.statics_removed} reservations removed`);
        parts.push(scopeBits.join(" / "));
      }
      parts.push(`${result.server_leases} leases on wire`);
      if (result.imported) parts.push(`${result.imported} imported`);
      if (result.refreshed) parts.push(`${result.refreshed} refreshed`);
      if (result.ipam_created || result.ipam_refreshed)
        parts.push(`IPAM ${result.ipam_created}+ / ${result.ipam_refreshed}~`);
      if (result.out_of_scope)
        parts.push(`${result.out_of_scope} out-of-scope`);
      if (result.mac_blocks_added || result.mac_blocks_removed)
        parts.push(
          `MAC blocks +${result.mac_blocks_added ?? 0}/-${result.mac_blocks_removed ?? 0}`,
        );
      if (result.errors.length)
        parts.push(`${result.errors.length} error(s): ${result.errors[0]}`);
      setSyncBanner(parts.join(" · "));
    },
    onError: (e) =>
      setSyncBanner(
        (e as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "Sync leases failed",
      ),
  });
  const approveMut = useMutation({
    mutationFn: () => dhcpApi.approveServer(server.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-servers"] }),
  });

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <StatusDot status={server.status} />
              <h1 className="text-lg font-semibold truncate">{server.name}</h1>
              <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
                {server.driver}
              </span>
              {server.ha_state && (
                <span
                  title={
                    server.ha_last_heartbeat_at
                      ? `Last HA heartbeat ${new Date(
                          server.ha_last_heartbeat_at,
                        ).toLocaleString()}`
                      : "No HA heartbeat received yet"
                  }
                  className={cn(
                    "rounded-full px-2 py-0.5 text-xs font-medium",
                    server.ha_state === "partner-down" ||
                      server.ha_state === "terminated"
                      ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                      : server.ha_state === "normal" ||
                          server.ha_state === "hot-standby" ||
                          server.ha_state === "load-balancing" ||
                          server.ha_state === "ready"
                        ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300"
                        : "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300",
                  )}
                >
                  HA: {server.ha_state}
                </span>
              )}
              {!server.agent_approved && !server.is_agentless && (
                <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
                  pending approval
                </span>
              )}
            </div>
            <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
              <span className="font-mono">
                {server.host}:{server.port}
              </span>
              {group && <span>Group: {group.name}</span>}
              <span>
                {server.last_sync_at
                  ? `Last sync ${new Date(server.last_sync_at).toLocaleString()}`
                  : "Never synced"}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {!server.agent_approved && !server.is_agentless && (
              <HeaderButton
                onClick={() => approveMut.mutate()}
                disabled={approveMut.isPending}
                className="bg-emerald-600 text-white hover:bg-emerald-700"
              >
                Approve
              </HeaderButton>
            )}
            {server.is_read_only ? (
              <HeaderButton
                icon={RefreshCw}
                iconClassName={leaseSyncMut.isPending ? "animate-spin" : ""}
                onClick={() => {
                  setSyncBanner(null);
                  leaseSyncMut.mutate();
                }}
                disabled={leaseSyncMut.isPending}
                title="Poll this server for active leases and mirror them into DHCP + IPAM"
              >
                Sync Leases
              </HeaderButton>
            ) : (
              <HeaderButton
                icon={RefreshCw}
                iconClassName={syncMut.isPending ? "animate-spin" : ""}
                onClick={() => syncMut.mutate(false)}
                disabled={syncMut.isPending}
              >
                Force Sync
              </HeaderButton>
            )}
            <HeaderButton icon={Pencil} onClick={onEdit}>
              Edit
            </HeaderButton>
            <HeaderButton
              variant="destructive"
              icon={Trash2}
              onClick={onDelete}
            >
              Delete
            </HeaderButton>
          </div>
        </div>
        {server.driver === "windows_dhcp" && (
          <div className="mt-3 rounded border border-sky-500/30 bg-sky-500/5 px-3 py-1.5 text-[11px] text-sky-700 dark:text-sky-400">
            Scope / pool / reservation edits on this server push to Windows DHCP
            via WinRM as you save. Source of truth lives on the DC; SpatiumDDI
            is a controller + mirror.
          </div>
        )}
        {groupOwnsConfig && group && (
          <div className="mt-3 flex items-center justify-between gap-3 rounded border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
            <span>
              Configuration (scopes, pools, reservations, classes, option
              templates, MAC blocks) is managed at the group level — every Kea
              peer in {group.name} renders the same config bundle.
            </span>
            {onSelectGroup && (
              <button
                type="button"
                onClick={() => onSelectGroup(group)}
                className="flex-shrink-0 rounded-md border border-amber-500/50 bg-amber-500/10 px-2.5 py-1 font-medium hover:bg-amber-500/20"
              >
                Open group →
              </button>
            )}
          </div>
        )}
        {adoptConflict && (
          <div className="mt-3 flex items-center justify-between gap-2 rounded border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
            <span>{adoptConflict}</span>
            <div className="flex flex-shrink-0 gap-1.5">
              <button
                type="button"
                onClick={() => syncMut.mutate(true)}
                disabled={syncMut.isPending}
                className="rounded-md border border-amber-500/50 bg-amber-500/10 px-2.5 py-1 font-medium hover:bg-amber-500/20 disabled:opacity-50"
              >
                Adopt existing &amp; sync
              </button>
              <button
                type="button"
                onClick={() => setAdoptConflict(null)}
                className="rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent"
              >
                dismiss
              </button>
            </div>
          </div>
        )}
        {syncBanner && (
          <div className="mt-3 flex items-center justify-between gap-2 rounded border bg-muted/40 px-3 py-1.5 text-xs">
            <span className="truncate">{syncBanner}</span>
            <button
              type="button"
              onClick={() => setSyncBanner(null)}
              className="rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent"
            >
              dismiss
            </button>
          </div>
        )}
      </div>

      <div className="border-b px-6 bg-card">
        <div className="flex gap-1">
          {!groupOwnsConfig && (
            <>
              <TabButton
                active={tab === "scopes"}
                onClick={() => setTab("scopes")}
              >
                Scopes
              </TabButton>
              <TabButton
                active={tab === "pools"}
                onClick={() => setTab("pools")}
              >
                Pools
              </TabButton>
              <TabButton
                active={tab === "statics"}
                onClick={() => setTab("statics")}
              >
                Static Assignments
              </TabButton>
              <TabButton
                active={tab === "classes"}
                onClick={() => setTab("classes")}
              >
                Client Classes
              </TabButton>
              <TabButton
                active={tab === "option-templates"}
                onClick={() => setTab("option-templates")}
              >
                Option Templates
              </TabButton>
              <TabButton
                active={tab === "mac-blocks"}
                onClick={() => setTab("mac-blocks")}
              >
                MAC Blocks
              </TabButton>
            </>
          )}
          <TabButton active={tab === "leases"} onClick={() => setTab("leases")}>
            Leases
          </TabButton>
          <TabButton
            active={tab === "history"}
            onClick={() => setTab("history")}
          >
            History
          </TabButton>
          <TabButton
            active={tab === "options"}
            onClick={() => setTab("options")}
          >
            Server Options
          </TabButton>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {!groupOwnsConfig && tab === "scopes" && (
          <ServerScopesTab groupId={server.server_group_id ?? ""} />
        )}
        {!groupOwnsConfig && tab === "pools" && (
          <ServerPoolsOrStaticsTab
            groupId={server.server_group_id ?? ""}
            kind="pools"
          />
        )}
        {!groupOwnsConfig && tab === "statics" && (
          <ServerPoolsOrStaticsTab
            groupId={server.server_group_id ?? ""}
            kind="statics"
          />
        )}
        {!groupOwnsConfig && tab === "classes" && (
          <ClientClassesTab groupId={server.server_group_id ?? ""} />
        )}
        {!groupOwnsConfig && tab === "option-templates" && (
          <OptionTemplatesTab groupId={server.server_group_id ?? ""} />
        )}
        {!groupOwnsConfig && tab === "mac-blocks" && (
          <MacBlocksTab groupId={server.server_group_id ?? ""} />
        )}
        {tab === "leases" && <LeasesTab server={server} />}
        {tab === "history" && <LeaseHistoryTab server={server} />}
        {tab === "options" && (
          <div className="rounded-lg border p-6 text-sm text-muted-foreground">
            Server-level default options (global pool, renew times, reservation
            defaults) are managed via the driver. Push changes with Force Sync.
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page shell
// ─────────────────────────────────────────────────────────────────────────────

export function DHCPPage() {
  useStickyLocation("spatium.lastUrl.dhcp");
  const qc = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectionState, setSelectionState] = useState<Selection>(null);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [editGroup, setEditGroup] = useState<DHCPServerGroup | null>(null);
  const [delGroup, setDelGroup] = useState<DHCPServerGroup | null>(null);
  const [delGroupNotice, setDelGroupNotice] = useState<string | null>(null);
  const [addServerFor, setAddServerFor] = useState<string | null>(null);
  const [editServer, setEditServer] = useState<DHCPServer | null>(null);
  const [delServer, setDelServer] = useState<DHCPServer | null>(null);
  // Issue #181: clicking a server from the GroupServersList opens the
  // ServerDetailModal as a quick read-only inspector. The full
  // standalone ServerDetailView is still reachable via the sidebar tree
  // and from the modal's "Open full view" button.
  const [modalServer, setModalServer] = useState<DHCPServer | null>(null);
  const urlRestored = useRef(false);

  // Pull cached group + server lists (populated by the sidebar query) so we
  // can resolve the selection from URL params on first mount.
  const { data: allGroups } = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
  });
  const { data: allServers } = useQuery({
    queryKey: ["dhcp-servers", "all"],
    queryFn: () => dhcpApi.listServers(),
  });

  // Update selection state + URL search params together so tab-switching away
  // and back reopens whatever the user last had selected. Uses `replace` to
  // avoid polluting browser history with every click.
  function setSelection(sel: Selection) {
    setSelectionState(sel);
    setSearchParams(
      (prev: URLSearchParams) => {
        const next = new URLSearchParams(prev);
        if (!sel) {
          next.delete("group");
          next.delete("server");
        } else if (sel.type === "group") {
          next.set("group", sel.group.id);
          next.delete("server");
        } else {
          if (sel.group) next.set("group", sel.group.id);
          else next.delete("group");
          next.set("server", sel.server.id);
        }
        return next;
      },
      { replace: true },
    );
  }

  const selection = selectionState;

  // URL-state restore: reopen last-visited group/server on back-navigation.
  // Depends on searchParams so that when `useStickyLocation` navigates from
  // bare `/dhcp` → `/dhcp?group=…` after mount, this effect re-runs and picks
  // up the now-populated params. The `urlRestored` guard is only set once
  // we've actually matched a param, so an early run with empty searchParams
  // doesn't latch us into "nothing to restore".
  useEffect(() => {
    if (urlRestored.current) return;
    if (!allGroups || !allServers) return;
    const groupId = searchParams.get("group");
    const serverId = searchParams.get("server");
    if (!groupId && !serverId) return;
    urlRestored.current = true;
    if (serverId) {
      const server = allServers.find((s: DHCPServer) => s.id === serverId);
      if (server) {
        const group =
          allGroups.find(
            (g: DHCPServerGroup) => g.id === server.server_group_id,
          ) ?? null;
        setSelectionState({ type: "server", group, server });
        return;
      }
    }
    if (groupId) {
      const group = allGroups.find((g: DHCPServerGroup) => g.id === groupId);
      if (group) setSelectionState({ type: "group", group });
    }
  }, [allGroups, allServers, searchParams]);

  const deleteGroupMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteGroup(id),
    onSuccess: (resp, id) => {
      // Two-person approval (#62): a covered delete returns 202 with a
      // queued change-request instead of deleting. Surface the message,
      // refresh the approval queue, and leave the group in place.
      if (handleApprovalQueued(resp)) {
        setDelGroupNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        return;
      }
      qc.invalidateQueries({ queryKey: ["dhcp-groups"] });
      if (selection && "group" in selection && selection.group?.id === id)
        setSelection(null);
      setDelGroup(null);
    },
  });
  const deleteGroupError =
    deleteGroupMut.error &&
    (((deleteGroupMut.error as { response?: { data?: { detail?: string } } })
      ?.response?.data?.detail as string | undefined) ??
      formatApiError(deleteGroupMut.error));
  const deleteServerMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteServer(id),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["dhcp-servers"] });
      if (selection?.type === "server" && selection.server.id === id)
        setSelection(null);
      setDelServer(null);
    },
  });

  // Refresh selected server on server-list invalidations so status badges
  // stay current.
  const selectedServerId =
    selection?.type === "server" ? selection.server.id : null;
  const { data: freshServer } = useQuery({
    queryKey: ["dhcp-server", selectedServerId],
    queryFn: () => dhcpApi.getServer(selectedServerId as string),
    enabled: !!selectedServerId,
    refetchInterval: 30_000,
  });
  const effectiveServer = useMemo(() => {
    if (selection?.type !== "server") return null;
    return freshServer ?? selection.server;
  }, [selection, freshServer]);

  return (
    <div className="flex h-full overflow-hidden">
      <GroupSidebar
        selection={selection}
        onSelect={setSelection}
        onCreateGroup={() => setShowCreateGroup(true)}
      />

      <div className="flex-1 overflow-hidden">
        {!selection && (
          <div className="flex h-full items-center justify-center">
            <div className="text-center">
              <Server className="h-12 w-12 text-muted-foreground/20 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">
                Select a server group or server from the sidebar.
              </p>
            </div>
          </div>
        )}
        {selection?.type === "group" && (
          <GroupDetailView
            group={selection.group}
            onEdit={() => setEditGroup(selection.group)}
            onDelete={() => setDelGroup(selection.group)}
            onAddServer={() => setAddServerFor(selection.group.id)}
            // Issue #181: open the read-only modal instead of
            // navigating to the full standalone server view. Mirrors
            // the DNS Servers tab UX.
            onSelectServer={(s) => setModalServer(s)}
            onEditServer={(s) => setEditServer(s)}
            onDeleteServer={(s) => setDelServer(s)}
          />
        )}
        {selection?.type === "server" && effectiveServer && (
          <ServerDetailView
            server={effectiveServer}
            group={selection.group}
            onEdit={() => setEditServer(effectiveServer)}
            onDelete={() => setDelServer(effectiveServer)}
            onSelectGroup={(g) => setSelection({ type: "group", group: g })}
          />
        )}
      </div>

      {showCreateGroup && (
        <CreateServerGroupModal onClose={() => setShowCreateGroup(false)} />
      )}
      {editGroup && (
        <CreateServerGroupModal
          group={editGroup}
          onClose={() => setEditGroup(null)}
        />
      )}
      {delGroup && (
        <DeleteConfirmModal
          title="Delete Server Group"
          description={`Permanently delete group "${delGroup.name}"? The group must be empty — move or delete its servers first.`}
          onConfirm={() => deleteGroupMut.mutate(delGroup.id)}
          onClose={() => {
            setDelGroup(null);
            setDelGroupNotice(null);
            deleteGroupMut.reset();
          }}
          isPending={deleteGroupMut.isPending}
          error={deleteGroupError || null}
          notice={delGroupNotice}
        />
      )}
      {addServerFor && (
        <CreateServerModal
          defaultGroupId={addServerFor}
          onClose={() => setAddServerFor(null)}
        />
      )}
      {editServer && (
        <CreateServerModal
          server={editServer}
          onClose={() => setEditServer(null)}
        />
      )}
      {delServer && (
        <DeleteConfirmModal
          title="Delete DHCP Server"
          description={`Remove server "${delServer.name}"? Its scopes remain but will be unassigned.`}
          onConfirm={() => deleteServerMut.mutate(delServer.id)}
          onClose={() => setDelServer(null)}
          isPending={deleteServerMut.isPending}
        />
      )}
      {modalServer && (
        <ServerDetailModal
          server={modalServer}
          onClose={() => setModalServer(null)}
        />
      )}
    </div>
  );
}

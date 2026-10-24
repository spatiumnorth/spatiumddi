import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import { ListPlus, Pencil, Plus, RefreshCw, Trash2, X } from "lucide-react";

import { MulticastDomainsTab } from "./MulticastDomainsPage";
import { MulticastReachabilityTab } from "./MulticastReachabilityTab";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import {
  customersApi,
  ipamApi,
  multicastApi,
  type IPSpace,
  type MulticastBulkAllocateItem,
  type MulticastBulkAllocateRequest,
  type MulticastGroupCreate,
  type MulticastGroupPortCreate,
  type MulticastGroupPortRead,
  type MulticastGroupRead,
  type MulticastGroupUpdate,
  type MulticastMembershipCreate,
  type MulticastMembershipRead,
  type MulticastMembershipRole,
  type MulticastPortTransport,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal, ModalTabs } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { IPAddressPicker } from "@/components/IPAddressPicker";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const TRANSPORTS: MulticastPortTransport[] = ["udp", "rtp", "tcp", "srt"];
const ROLES: MulticastMembershipRole[] = [
  "producer",
  "consumer",
  "rendezvous_point",
];

function RoleBadge({ role }: { role: string }) {
  const styles: Record<string, string> = {
    producer:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    consumer: "bg-sky-100 text-sky-700 dark:bg-sky-950/30 dark:text-sky-400",
    rendezvous_point:
      "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-400",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        styles[role] ?? "bg-zinc-200 text-zinc-700",
      )}
    >
      {role.replace("_", " ")}
    </span>
  );
}

// ── Editor modal ────────────────────────────────────────────────────

type EditorTab = "general" | "ports" | "memberships";

function MulticastGroupModal({
  existing,
  spaces,
  onClose,
}: {
  existing: MulticastGroupRead | null;
  spaces: IPSpace[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [tab, setTab] = useState<EditorTab>("general");

  // ── identity ──
  const [spaceId, setSpaceId] = useState(existing?.space_id ?? "");
  const [address, setAddress] = useState(existing?.address ?? "");
  const [name, setName] = useState(existing?.name ?? "");
  const [application, setApplication] = useState(existing?.application ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [rtpPayloadType, setRtpPayloadType] = useState(
    existing?.rtp_payload_type != null ? String(existing.rtp_payload_type) : "",
  );
  const [bandwidth, setBandwidth] = useState(
    existing?.bandwidth_mbps_estimate ?? "",
  );
  const [customerId, setCustomerId] = useState<string | null>(
    existing?.customer_id ?? null,
  );
  const [domainId, setDomainId] = useState<string | null>(
    existing?.domain_id ?? null,
  );

  const [error, setError] = useState<string | null>(null);

  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const customers = customersQ.data?.items ?? [];

  const domainsQ = useQuery({
    queryKey: ["multicast-domains"],
    queryFn: () => multicastApi.listDomains(),
    staleTime: 60_000,
  });
  const domains = domainsQ.data ?? [];

  const mut = useMutation({
    mutationFn: async () => {
      if (!spaceId) throw new Error("IP space is required");
      if (!address.trim()) throw new Error("Address is required");
      if (!name.trim()) throw new Error("Name is required");
      const body: MulticastGroupCreate | MulticastGroupUpdate = {
        space_id: spaceId,
        address: address.trim(),
        name: name.trim(),
        application: application.trim(),
        description,
        rtp_payload_type: rtpPayloadType ? Number(rtpPayloadType) : null,
        bandwidth_mbps_estimate: bandwidth || null,
        customer_id: customerId,
        domain_id: domainId,
      };
      if (existing) {
        // PUT only — drop space_id since the backend update schema
        // doesn't accept it (a group can't change spaces in this
        // wave; that's a Wave 3 / Phase 2 conversation).
        const upd: MulticastGroupUpdate = { ...body };
        delete (upd as { space_id?: string }).space_id;
        return multicastApi.update(existing.id, upd);
      }
      return multicastApi.create(body as MulticastGroupCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["multicast-groups"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string | { msg?: string }[] } };
      };
      const detail = err?.response?.data?.detail;
      if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg ?? "validation error").join("; "));
      } else {
        setError(detail ?? err?.message ?? "Save failed");
      }
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New multicast group"}
      wide
    >
      <div className="space-y-3 pb-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Name
            </label>
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Cam7 Studio-B HD"
              autoFocus={!existing}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Address
            </label>
            <input
              className={cn(inputCls, "font-mono")}
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="239.5.7.42 or ff05::1:3"
            />
          </div>
        </div>
      </div>

      <ModalTabs<EditorTab>
        tabs={[
          { key: "general", label: "General" },
          ...(existing
            ? ([
                { key: "ports" as EditorTab, label: "Ports" },
                { key: "memberships" as EditorTab, label: "Memberships" },
              ] as const)
            : []),
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === "general" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              IP space
            </label>
            <select
              className={inputCls}
              value={spaceId}
              onChange={(e) => setSpaceId(e.target.value)}
              disabled={!!existing}
            >
              <option value="">— select —</option>
              {spaces.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            {existing && (
              <p className="mt-1 text-[10px] text-muted-foreground">
                Space is fixed after creation.
              </p>
            )}
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Customer (optional)
            </label>
            <select
              className={inputCls}
              value={customerId ?? ""}
              onChange={(e) => setCustomerId(e.target.value || null)}
            >
              <option value="">— None —</option>
              {customers.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              PIM domain (optional)
            </label>
            <select
              className={inputCls}
              value={domainId ?? ""}
              onChange={(e) => setDomainId(e.target.value || null)}
            >
              <option value="">— None —</option>
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} · {d.pim_mode}
                </option>
              ))}
            </select>
            <p className="mt-1 text-[10px] text-muted-foreground">
              Network-layer routing context — manage domains under{" "}
              <strong>Multicast → View domains</strong>.
            </p>
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Application
            </label>
            <input
              className={inputCls}
              value={application}
              onChange={(e) => setApplication(e.target.value)}
              placeholder="e.g. SMPTE 2110-20 video / Dante audio / market data feed"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              RTP payload type (0-127)
            </label>
            <input
              className={inputCls}
              value={rtpPayloadType}
              onChange={(e) => setRtpPayloadType(e.target.value)}
              placeholder="e.g. 96"
              inputMode="numeric"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Estimated bandwidth (Mbps)
            </label>
            <input
              className={inputCls}
              value={bandwidth}
              onChange={(e) => setBandwidth(e.target.value)}
              placeholder="e.g. 1485 (SDI HD) / 2.5 (audio flow)"
            />
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Description
            </label>
            <textarea
              className={cn(inputCls, "min-h-[80px]")}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional free-text description."
            />
          </div>
        </div>
      )}

      {tab === "ports" && existing && <PortsTab groupId={existing.id} />}
      {tab === "memberships" && existing && (
        <MembershipsTab groupId={existing.id} />
      )}

      {error && <p className="mt-3 text-sm text-destructive">{error}</p>}

      <div className="mt-6 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Close
        </button>
        {tab === "general" && (
          <button
            type="button"
            disabled={mut.isPending}
            onClick={() => mut.mutate()}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        )}
      </div>
    </Modal>
  );
}

// ── Ports tab ───────────────────────────────────────────────────────

function PortsTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const [portStart, setPortStart] = useState("");
  const [portEnd, setPortEnd] = useState("");
  const [transport, setTransport] = useState<MulticastPortTransport>("udp");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["multicast-ports", groupId],
    queryFn: () => multicastApi.listPorts(groupId),
  });

  const add = useMutation({
    mutationFn: (data: MulticastGroupPortCreate) =>
      multicastApi.createPort(groupId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["multicast-ports", groupId] });
      setPortStart("");
      setPortEnd("");
      setNotes("");
      setError(null);
    },
    onError: (e: unknown) => {
      const err = e as { response?: { data?: { detail?: string } } };
      setError(err?.response?.data?.detail ?? "Add failed");
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => multicastApi.deletePort(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["multicast-ports", groupId] });
    },
  });

  const ports = q.data ?? [];

  return (
    <div className="space-y-3">
      <div className="rounded-md border bg-muted/20 p-3">
        <p className="mb-2 text-xs font-medium text-muted-foreground">
          Add a port range
        </p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[110px_110px_120px_1fr_auto]">
          <input
            className={inputCls}
            placeholder="Port"
            value={portStart}
            onChange={(e) => setPortStart(e.target.value)}
            inputMode="numeric"
          />
          <input
            className={inputCls}
            placeholder="End (opt)"
            value={portEnd}
            onChange={(e) => setPortEnd(e.target.value)}
            inputMode="numeric"
          />
          <select
            className={inputCls}
            value={transport}
            onChange={(e) =>
              setTransport(e.target.value as MulticastPortTransport)
            }
          >
            {TRANSPORTS.map((t) => (
              <option key={t} value={t}>
                {t.toUpperCase()}
              </option>
            ))}
          </select>
          <input
            className={inputCls}
            placeholder="Notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
          <button
            type="button"
            disabled={add.isPending || !portStart}
            onClick={() =>
              add.mutate({
                port_start: Number(portStart),
                port_end: portEnd ? Number(portEnd) : null,
                transport,
                notes,
              })
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            Add
          </button>
        </div>
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
      </div>

      {ports.length === 0 ? (
        <p className="px-2 py-6 text-center text-xs text-muted-foreground">
          No ports defined yet.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <tr className="border-b">
              <th className="px-2 py-1.5">Port</th>
              <th className="px-2 py-1.5">Transport</th>
              <th className="px-2 py-1.5">Notes</th>
              <th className="px-2 py-1.5"></th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {ports.map((p) => (
              <PortRow
                key={p.id}
                row={p}
                onDelete={() => remove.mutate(p.id)}
              />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function PortRow({
  row,
  onDelete,
}: {
  row: MulticastGroupPortRead;
  onDelete: () => void;
}) {
  const range =
    row.port_end != null
      ? `${row.port_start}–${row.port_end}`
      : String(row.port_start);
  return (
    <tr className="border-b">
      <td className="px-2 py-1.5 font-mono">{range}</td>
      <td className="px-2 py-1.5">{row.transport.toUpperCase()}</td>
      <td className="px-2 py-1.5 text-muted-foreground">{row.notes || "—"}</td>
      <td className="px-2 py-1.5 text-right">
        <button
          type="button"
          onClick={onDelete}
          title="Delete port"
          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </td>
    </tr>
  );
}

// ── Memberships tab ─────────────────────────────────────────────────

function MembershipsTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const [ipId, setIpId] = useState<string | null>(null);
  const [_ipLabel, setIpLabel] = useState<string | null>(null);
  const [role, setRole] = useState<MulticastMembershipRole>("consumer");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["multicast-memberships", groupId],
    queryFn: () => multicastApi.listMemberships(groupId),
  });

  const add = useMutation({
    mutationFn: (data: MulticastMembershipCreate) =>
      multicastApi.createMembership(groupId, data),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["multicast-memberships", groupId],
      });
      setIpId(null);
      setIpLabel(null);
      setNotes("");
      setError(null);
    },
    onError: (e: unknown) => {
      const err = e as { response?: { data?: { detail?: string } } };
      setError(err?.response?.data?.detail ?? "Add failed");
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => multicastApi.deleteMembership(id),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["multicast-memberships", groupId],
      });
    },
  });

  const memberships = q.data ?? [];

  return (
    <div className="space-y-3">
      <div className="rounded-md border bg-muted/20 p-3">
        <p className="mb-2 text-xs font-medium text-muted-foreground">
          Attach a producer / consumer / RP
        </p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_180px_1fr_auto]">
          <IPAddressPicker
            value={ipId}
            onChange={(id, label) => {
              setIpId(id);
              setIpLabel(label);
            }}
          />
          <select
            className={inputCls}
            value={role}
            onChange={(e) => setRole(e.target.value as MulticastMembershipRole)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r.replace("_", " ")}
              </option>
            ))}
          </select>
          <input
            className={inputCls}
            placeholder="Notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
          <button
            type="button"
            disabled={add.isPending || !ipId}
            onClick={() =>
              ipId &&
              add.mutate({
                ip_address_id: ipId,
                role,
                notes,
              })
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            Add
          </button>
        </div>
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
      </div>

      {memberships.length === 0 ? (
        <p className="px-2 py-6 text-center text-xs text-muted-foreground">
          No memberships yet.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <tr className="border-b">
              <th className="px-2 py-1.5">IP address ID</th>
              <th className="px-2 py-1.5">Role</th>
              <th className="px-2 py-1.5">Source</th>
              <th className="px-2 py-1.5">Notes</th>
              <th className="px-2 py-1.5"></th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {memberships.map((m) => (
              <MembershipRow
                key={m.id}
                row={m}
                onDelete={() => remove.mutate(m.id)}
              />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function MembershipRow({
  row,
  onDelete,
}: {
  row: MulticastMembershipRead;
  onDelete: () => void;
}) {
  return (
    <tr className="border-b">
      <td className="px-2 py-1.5 font-mono text-[10px] text-muted-foreground">
        {row.ip_address_id}
      </td>
      <td className="px-2 py-1.5">
        <RoleBadge role={row.role} />
      </td>
      <td className="px-2 py-1.5 text-muted-foreground">
        {row.seen_via.replace("_", " ")}
      </td>
      <td className="px-2 py-1.5 text-muted-foreground">{row.notes || "—"}</td>
      <td className="px-2 py-1.5 text-right">
        <button
          type="button"
          onClick={onDelete}
          title="Remove membership"
          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </td>
    </tr>
  );
}

// ── Bulk allocate modal ─────────────────────────────────────────────

function BulkAllocateModal({
  spaces,
  onClose,
}: {
  spaces: IPSpace[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [spaceId, setSpaceId] = useState(spaces[0]?.id ?? "");
  const [startAddress, setStartAddress] = useState("239.10.0.0");
  const [count, setCount] = useState("8");
  const [nameTemplate, setNameTemplate] = useState("stream-{n:03d}");
  const [templateStart, setTemplateStart] = useState("1");
  const [application, setApplication] = useState("");
  const [customerId, setCustomerId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<MulticastBulkAllocateItem[] | null>(
    null,
  );
  const [conflictCount, setConflictCount] = useState(0);

  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const customers = customersQ.data?.items ?? [];

  function buildBody(): MulticastBulkAllocateRequest {
    return {
      space_id: spaceId,
      count: Number(count),
      name_template: nameTemplate,
      start_address: startAddress.trim(),
      template_start: Number(templateStart) || 0,
      application,
      customer_id: customerId,
    };
  }

  const previewMut = useMutation({
    mutationFn: () => multicastApi.bulkAllocatePreview(buildBody()),
    onSuccess: (res) => {
      setPreview(res.items);
      setConflictCount(res.conflict_count);
      setError(null);
    },
    onError: (e: unknown) => {
      const err = e as {
        response?: { data?: { detail?: string | { msg?: string }[] } };
      };
      const detail = err?.response?.data?.detail;
      if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg ?? "validation error").join("; "));
      } else {
        setError(detail ?? "Preview failed");
      }
    },
  });

  const commitMut = useMutation({
    mutationFn: () => multicastApi.bulkAllocateCommit(buildBody()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["multicast-groups"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        response?: {
          data?: {
            detail?: string | { message?: string; conflicts?: string[] };
          };
        };
      };
      const detail = err?.response?.data?.detail;
      if (typeof detail === "object" && detail && "message" in detail) {
        const conflicts = detail.conflicts?.slice(0, 5).join(", ") ?? "";
        setError(
          `${detail.message ?? "Commit failed"}${conflicts ? ` — ${conflicts}…` : ""}`,
        );
      } else if (typeof detail === "string") {
        setError(detail);
      } else {
        setError("Commit failed");
      }
    },
  });

  return (
    <Modal onClose={onClose} title="Bulk allocate multicast groups" wide>
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              IP space
            </label>
            <select
              className={inputCls}
              value={spaceId}
              onChange={(e) => {
                setSpaceId(e.target.value);
                setPreview(null);
              }}
            >
              <option value="">— select —</option>
              {spaces.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Customer (optional)
            </label>
            <select
              className={inputCls}
              value={customerId ?? ""}
              onChange={(e) => setCustomerId(e.target.value || null)}
            >
              <option value="">— None —</option>
              {customers.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Start address
            </label>
            <input
              className={cn(inputCls, "font-mono")}
              value={startAddress}
              onChange={(e) => {
                setStartAddress(e.target.value);
                setPreview(null);
              }}
              placeholder="239.10.0.0"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Count (max 256)
            </label>
            <input
              className={inputCls}
              value={count}
              onChange={(e) => {
                setCount(e.target.value);
                setPreview(null);
              }}
              inputMode="numeric"
            />
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Name template
            </label>
            <input
              className={cn(inputCls, "font-mono")}
              value={nameTemplate}
              onChange={(e) => {
                setNameTemplate(e.target.value);
                setPreview(null);
              }}
              placeholder="stream-{n:03d}"
            />
            <p className="mt-1 text-[10px] text-muted-foreground">
              Tokens: <code>{`{n}`}</code> / <code>{`{n:03d}`}</code> /{" "}
              <code>{`{n:x}`}</code> / <code>{`{oct1}`}</code>–
              <code>{`{oct4}`}</code>. Same grammar as the IPAM bulk-allocate.
            </p>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Template start (n initial value)
            </label>
            <input
              className={inputCls}
              value={templateStart}
              onChange={(e) => {
                setTemplateStart(e.target.value);
                setPreview(null);
              }}
              inputMode="numeric"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Application
            </label>
            <input
              className={inputCls}
              value={application}
              onChange={(e) => setApplication(e.target.value)}
              placeholder="e.g. SMPTE 2110-20 video"
            />
          </div>
        </div>

        {preview && (
          <div className="rounded-md border">
            <div className="flex items-center justify-between border-b bg-muted/30 px-3 py-1.5 text-xs">
              <span className="font-medium">
                Preview — {preview.length} address(es)
                {conflictCount > 0 && (
                  <span className="ml-2 text-destructive">
                    ({conflictCount} conflict{conflictCount === 1 ? "" : "s"})
                  </span>
                )}
              </span>
              <span className="text-muted-foreground">
                Commit refuses if any conflicts remain.
              </span>
            </div>
            <div className="max-h-72 overflow-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <tr className="border-b">
                    <th className="px-3 py-1.5">#</th>
                    <th className="px-3 py-1.5">Address</th>
                    <th className="px-3 py-1.5">Name</th>
                    <th className="px-3 py-1.5">Status</th>
                  </tr>
                </thead>
                <tbody className={zebraBodyCls}>
                  {preview.map((item, idx) => (
                    <tr
                      key={item.address}
                      className={cn(
                        "border-b",
                        item.conflict && "bg-destructive/5",
                      )}
                    >
                      <td className="px-3 py-1 tabular-nums text-muted-foreground">
                        {idx + 1}
                      </td>
                      <td className="px-3 py-1 font-mono">{item.address}</td>
                      <td className="px-3 py-1">{item.name}</td>
                      <td className="px-3 py-1">
                        {item.conflict ? (
                          <span className="text-destructive">in use</span>
                        ) : (
                          <span className="text-emerald-600 dark:text-emerald-400">
                            free
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {error && <p className="text-sm text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={previewMut.isPending || !spaceId || !startAddress}
            onClick={() => previewMut.mutate()}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
          >
            {previewMut.isPending ? "Previewing…" : "Preview"}
          </button>
          <button
            type="button"
            disabled={
              !preview ||
              conflictCount > 0 ||
              commitMut.isPending ||
              previewMut.isPending
            }
            onClick={() => commitMut.mutate()}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {commitMut.isPending ? "Creating…" : "Commit"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Page ────────────────────────────────────────────────────────────

export function MulticastGroupsPage() {
  const qc = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  // ``?space=<uuid>`` deep-links from the IPAM page so clicking
  // through from a multicast IPSpace lands here pre-filtered.
  const [search, setSearch] = useState("");
  const [spaceFilter, setSpaceFilter] = useState(
    () => searchParams.get("space") ?? "",
  );
  const [customerFilter, setCustomerFilter] = useState("");
  const [editing, setEditing] = useState<MulticastGroupRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [showBulk, setShowBulk] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const { enabled: featureEnabled } = useFeatureModules();
  // BGP Looking Glass reachability cross-check (issue #566 Phase 6) is
  // only meaningful when the Looking Glass module is on — no RIB to
  // cross-reference against otherwise.
  const lgEnabled = featureEnabled("network.looking_glass");
  const tab: "groups" | "domains" | "reachability" =
    searchParams.get("tab") === "domains"
      ? "domains"
      : searchParams.get("tab") === "reachability" && lgEnabled
        ? "reachability"
        : "groups";

  // Keep ``?space=<uuid>`` in the URL in sync with the dropdown.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        if (spaceFilter) params.set("space", spaceFilter);
        else params.delete("space");
        return params;
      },
      { replace: true },
    );
  }, [spaceFilter, setSearchParams]);

  function selectTab(next: "groups" | "domains" | "reachability") {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        if (next === "groups") params.delete("tab");
        else params.set("tab", next);
        return params;
      },
      { replace: true },
    );
  }

  const spacesQ = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: () => ipamApi.listSpaces(),
    staleTime: 60_000,
  });
  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  const query = useQuery({
    queryKey: ["multicast-groups", search, spaceFilter, customerFilter],
    queryFn: () =>
      multicastApi.list({
        limit: 500,
        search: search || undefined,
        space_id: spaceFilter || undefined,
        customer_id: customerFilter || undefined,
      }),
  });

  const items = query.data?.items ?? [];

  const removeOne = useMutation({
    mutationFn: (id: string) => multicastApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["multicast-groups"] }),
  });

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => multicastApi.bulkDelete(ids),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["multicast-groups"] });
    },
  });

  const allChecked = useMemo(
    () => items.length > 0 && items.every((g) => selectedIds.has(g.id)),
    [items, selectedIds],
  );

  function toggleOne(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (allChecked) setSelectedIds(new Set());
    else setSelectedIds(new Set(items.map((g) => g.id)));
  }

  const customerNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of customersQ.data?.items ?? []) {
      map.set(c.id, c.name);
    }
    return map;
  }, [customersQ.data]);

  const spaceNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of spacesQ.data ?? []) {
      map.set(s.id, s.name);
    }
    return map;
  }, [spacesQ.data]);

  // Default the space filter when spaces first load — saves an
  // operator click when there's only one IPSpace in the deployment.
  useEffect(() => {
    if (!spaceFilter && spacesQ.data && spacesQ.data.length === 1) {
      setSpaceFilter(spacesQ.data[0].id);
    }
  }, [spacesQ.data, spaceFilter]);

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div>
          <h1 className="text-xl font-semibold">Multicast</h1>
          <p className="text-sm text-muted-foreground">
            Stream identities for SMPTE 2110 / Dante / NDI / market-data
            deployments. Each group is an address (+ optional ports) with
            producer / consumer / rendezvous-point memberships; PIM domains
            carry the network-layer routing context.
          </p>
        </div>

        {/* Sub-tab bar — switches between the groups list (default)
            and the PIM-domain registry. URL param ``?tab=domains``
            keeps the choice deep-linkable. */}
        <div className="flex gap-1 border-b">
          <TabPill
            active={tab === "groups"}
            onClick={() => selectTab("groups")}
            label="Groups"
          />
          <TabPill
            active={tab === "domains"}
            onClick={() => selectTab("domains")}
            label="Domains"
          />
          {lgEnabled && (
            <TabPill
              active={tab === "reachability"}
              onClick={() => selectTab("reachability")}
              label="BGP Reachability"
            />
          )}
        </div>

        {tab === "reachability" && lgEnabled ? (
          <MulticastReachabilityTab />
        ) : tab === "domains" ? (
          <MulticastDomainsTab />
        ) : (
          <GroupsTabBody
            query={query}
            items={items}
            spaceFilter={spaceFilter}
            setSpaceFilter={setSpaceFilter}
            customerFilter={customerFilter}
            setCustomerFilter={setCustomerFilter}
            search={search}
            setSearch={setSearch}
            spaces={spacesQ.data ?? []}
            customers={customersQ.data?.items ?? []}
            spaceNames={spaceNames}
            customerNames={customerNames}
            selectedIds={selectedIds}
            allChecked={allChecked}
            toggleAll={toggleAll}
            toggleOne={toggleOne}
            removeOne={removeOne}
            bulkDelete={bulkDelete}
            setEditing={setEditing}
            setShowNew={setShowNew}
            setShowBulk={setShowBulk}
          />
        )}
      </div>

      {(showNew || editing) && (
        <MulticastGroupModal
          existing={editing}
          spaces={spacesQ.data ?? []}
          onClose={() => {
            setShowNew(false);
            setEditing(null);
          }}
        />
      )}
      {showBulk && (
        <BulkAllocateModal
          spaces={spacesQ.data ?? []}
          onClose={() => setShowBulk(false)}
        />
      )}
    </div>
  );
}

// ── Tab pill ────────────────────────────────────────────────────────

function TabPill({
  active,
  onClick,
  label,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "border-b-2 px-3 py-2 text-sm font-medium transition-colors -mb-px",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}

// ── Groups tab body ─────────────────────────────────────────────────
//
// Lifted out of the page wrapper so the wrapper can render either
// this body or ``<MulticastDomainsTab />`` based on the active sub-
// tab. State stays at the wrapper level so a tab-flip away and back
// preserves the operator's filter / selection in the same session.

type GroupsTabBodyProps = {
  query: { refetch: () => void; isFetching: boolean; error?: unknown };
  items: MulticastGroupRead[];
  spaceFilter: string;
  setSpaceFilter: (v: string) => void;
  customerFilter: string;
  setCustomerFilter: (v: string) => void;
  search: string;
  setSearch: (v: string) => void;
  spaces: IPSpace[];
  customers: { id: string; name: string }[];
  spaceNames: Map<string, string>;
  customerNames: Map<string, string>;
  selectedIds: Set<string>;
  allChecked: boolean;
  toggleAll: () => void;
  toggleOne: (id: string) => void;
  removeOne: { mutate: (id: string) => void };
  bulkDelete: { mutate: (ids: string[]) => void; isPending: boolean };
  setEditing: (g: MulticastGroupRead | null) => void;
  setShowNew: (v: boolean) => void;
  setShowBulk: (v: boolean) => void;
};

function GroupsTabBody({
  query,
  items,
  spaceFilter,
  setSpaceFilter,
  customerFilter,
  setCustomerFilter,
  search,
  setSearch,
  spaces,
  customers,
  spaceNames,
  customerNames,
  selectedIds,
  allChecked,
  toggleAll,
  toggleOne,
  removeOne,
  bulkDelete,
  setEditing,
  setShowNew,
  setShowBulk,
}: GroupsTabBodyProps) {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'multicast'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "multicast"),
    "Requires write permission on multicast groups",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "multicast"),
    "Requires delete permission on multicast groups",
  );
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);
  return (
    <>
      <div className="flex justify-end gap-2">
        <HeaderButton
          icon={RefreshCw}
          onClick={() => query.refetch()}
          iconClassName={query.isFetching ? "animate-spin" : undefined}
        >
          Refresh
        </HeaderButton>
        <HeaderButton
          icon={ListPlus}
          onClick={() => setShowBulk(true)}
          {...writeGate}
        >
          Bulk allocate…
        </HeaderButton>
        <HeaderButton
          variant="primary"
          icon={Plus}
          onClick={() => setShowNew(true)}
          {...writeGate}
        >
          New group
        </HeaderButton>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <input
          className={cn(inputCls, "max-w-xs")}
          placeholder="Search name / application / address…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className={cn(inputCls, "max-w-[220px]")}
          value={spaceFilter}
          onChange={(e) => setSpaceFilter(e.target.value)}
        >
          <option value="">All spaces</option>
          {spaces.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <select
          className={cn(inputCls, "max-w-[200px]")}
          value={customerFilter}
          onChange={(e) => setCustomerFilter(e.target.value)}
        >
          <option value="">All customers</option>
          {customers.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </div>

      {selectedIds.size > 0 && (
        <div className="flex items-center justify-between rounded-md border bg-muted/50 px-3 py-2 text-sm">
          <span>{selectedIds.size} selected</span>
          <HeaderButton
            variant="destructive"
            icon={Trash2}
            disabled={bulkDelete.isPending}
            onClick={() => {
              const ids = Array.from(selectedIds);
              setConfirm({
                title: "Delete multicast groups",
                message: `Delete ${ids.length} multicast group${ids.length === 1 ? "" : "s"}? Ports + memberships cascade.`,
                confirmLabel: "Delete",
                onConfirm: () => bulkDelete.mutate(ids),
              });
            }}
            {...deleteGate}
          >
            Delete selected
          </HeaderButton>
        </div>
      )}

      <div className="rounded-md border">
        <table className="w-full text-sm">
          <thead className="text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <tr className="border-b bg-muted/30">
              <th className="w-8 px-3 py-2">
                <input
                  type="checkbox"
                  checked={allChecked}
                  onChange={toggleAll}
                  aria-label="Select all"
                />
              </th>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Application</th>
              <th className="px-3 py-2">Space</th>
              <th className="px-3 py-2">Customer</th>
              <th className="px-3 py-2">Bandwidth</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {items.length === 0 && !query.isFetching && (
              <tr>
                <td
                  colSpan={8}
                  className="px-3 py-10 text-center text-sm text-muted-foreground"
                >
                  <ListEmpty
                    error={query.error}
                    what="multicast groups"
                    filtered={
                      search !== "" ||
                      spaceFilter !== "" ||
                      customerFilter !== ""
                    }
                    onClearFilters={() => {
                      setSearch("");
                      setSpaceFilter("");
                      setCustomerFilter("");
                    }}
                  >
                    No multicast groups yet. Click <strong>New group</strong> to
                    add the first.
                  </ListEmpty>
                </td>
              </tr>
            )}
            {items.map((g) => (
              <tr key={g.id} className="border-b hover:bg-muted/30">
                <td className="px-3 py-1.5">
                  <input
                    type="checkbox"
                    checked={selectedIds.has(g.id)}
                    onChange={() => toggleOne(g.id)}
                    aria-label={`Select ${g.address}`}
                  />
                </td>
                <td className="px-3 py-1.5 font-mono">{g.address}</td>
                <td className="px-3 py-1.5">{g.name}</td>
                <td className="px-3 py-1.5 text-muted-foreground">
                  {g.application || "—"}
                </td>
                <td className="px-3 py-1.5 text-muted-foreground">
                  {spaceNames.get(g.space_id) ?? g.space_id.slice(0, 8)}
                </td>
                <td className="px-3 py-1.5 text-muted-foreground">
                  {g.customer_id
                    ? (customerNames.get(g.customer_id) ??
                      g.customer_id.slice(0, 8))
                    : "—"}
                </td>
                <td className="px-3 py-1.5 tabular-nums text-muted-foreground">
                  {g.bandwidth_mbps_estimate
                    ? `${g.bandwidth_mbps_estimate} Mbps`
                    : "—"}
                </td>
                <td className="px-3 py-1.5 text-right">
                  <button
                    type="button"
                    onClick={() => setEditing(g)}
                    title="Edit"
                    className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                    {...writeGate}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setConfirm({
                        title: "Delete multicast group",
                        message: `Delete multicast group ${g.address}?`,
                        confirmLabel: "Delete",
                        onConfirm: () => removeOne.mutate(g.id),
                      });
                    }}
                    title="Delete"
                    className="ml-1 rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                    {...deleteGate}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ConfirmModal
        open={confirm !== null}
        title={confirm?.title ?? ""}
        message={confirm?.message ?? ""}
        confirmLabel={confirm?.confirmLabel}
        tone="destructive"
        onConfirm={() => {
          confirm?.onConfirm();
          setConfirm(null);
        }}
        onClose={() => setConfirm(null)}
      />
    </>
  );
}

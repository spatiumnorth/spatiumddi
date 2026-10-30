import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import {
  ipamApi,
  natApi,
  type NATKind,
  type NATMapping,
  type NATMappingWrite,
  type NATProtocol,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Link } from "react-router-dom";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { useFeatureModules } from "@/hooks/useFeatureModules";

const KIND_LABEL: Record<NATKind, string> = {
  "1to1": "1:1 NAT",
  pat: "PAT",
  hide: "Hide / Masquerade",
};

function pickPort(start: number | null, end: number | null): string {
  if (start == null && end == null) return "—";
  if (start === end) return String(start);
  return `${start ?? "?"}–${end ?? "?"}`;
}

// ─────────────────────────────────────────────────────────────────────
// Modal
// ─────────────────────────────────────────────────────────────────────

function NATMappingModal({
  initial,
  onClose,
  onSaved,
}: {
  initial: NATMapping | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const editing = initial != null;
  const [name, setName] = useState(initial?.name ?? "");
  const [kind, setKind] = useState<NATKind>(initial?.kind ?? "1to1");
  const [internalIp, setInternalIp] = useState(initial?.internal_ip ?? "");
  const [internalSubnetId, setInternalSubnetId] = useState(
    initial?.internal_subnet_id ?? "",
  );
  const [internalPortStart, setInternalPortStart] = useState<string>(
    initial?.internal_port_start != null
      ? String(initial.internal_port_start)
      : "",
  );
  const [internalPortEnd, setInternalPortEnd] = useState<string>(
    initial?.internal_port_end != null ? String(initial.internal_port_end) : "",
  );
  const [externalIp, setExternalIp] = useState(initial?.external_ip ?? "");
  const [externalPortStart, setExternalPortStart] = useState<string>(
    initial?.external_port_start != null
      ? String(initial.external_port_start)
      : "",
  );
  const [externalPortEnd, setExternalPortEnd] = useState<string>(
    initial?.external_port_end != null ? String(initial.external_port_end) : "",
  );
  const [protocol, setProtocol] = useState<NATProtocol>(
    initial?.protocol ?? "any",
  );
  const [deviceLabel, setDeviceLabel] = useState(initial?.device_label ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
    enabled: kind === "hide",
  });

  const saveMut = useMutation({
    mutationFn: (body: NATMappingWrite) =>
      editing && initial
        ? natApi.update(initial.id, body)
        : natApi.create(body),
    onSuccess: () => {
      onSaved();
      onClose();
    },
    onError: (err: unknown) => {
      setError(formatApiError(err, "Save failed"));
    },
  });

  function toIntOrNull(s: string): number | null {
    const t = s.trim();
    if (!t) return null;
    const n = Number(t);
    return Number.isFinite(n) ? n : null;
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const showPorts = kind === "pat";
    const showInternalIp = kind === "1to1" || kind === "pat";
    const showSubnet = kind === "hide";

    const body: NATMappingWrite = {
      name: name.trim(),
      kind,
      internal_ip: showInternalIp && internalIp ? internalIp.trim() : null,
      internal_subnet_id:
        showSubnet && internalSubnetId ? internalSubnetId : null,
      internal_port_start: showPorts ? toIntOrNull(internalPortStart) : null,
      internal_port_end: showPorts ? toIntOrNull(internalPortEnd) : null,
      external_ip: externalIp ? externalIp.trim() : null,
      external_port_start: showPorts ? toIntOrNull(externalPortStart) : null,
      external_port_end: showPorts ? toIntOrNull(externalPortEnd) : null,
      protocol,
      device_label: deviceLabel.trim() || null,
      description: description.trim() || null,
    };
    saveMut.mutate(body);
  }

  const showInternalIp = kind === "1to1" || kind === "pat";
  const showSubnet = kind === "hide";
  const showPorts = kind === "pat";

  return (
    <Modal
      title={editing ? "Edit NAT mapping" : "New NAT mapping"}
      onClose={onClose}
    >
      <form onSubmit={submit} className="space-y-3 p-4">
        <div>
          <label className="block text-xs font-medium">Name</label>
          <input
            className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            maxLength={128}
          />
        </div>
        <div>
          <label className="block text-xs font-medium">Kind</label>
          <select
            className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
            value={kind}
            onChange={(e) => setKind(e.target.value as NATKind)}
          >
            <option value="1to1">1:1 NAT</option>
            <option value="pat">PAT (port-translated)</option>
            <option value="hide">Hide / Masquerade (subnet → IP)</option>
          </select>
        </div>

        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {showInternalIp && (
            <div>
              <label className="block text-xs font-medium">Internal IP</label>
              <input
                className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-sm"
                value={internalIp}
                onChange={(e) => setInternalIp(e.target.value)}
                placeholder="10.0.0.10"
              />
            </div>
          )}
          {showSubnet && (
            <div>
              <label className="block text-xs font-medium">
                Internal subnet
              </label>
              <select
                className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
                value={internalSubnetId}
                onChange={(e) => setInternalSubnetId(e.target.value)}
              >
                <option value="">— select —</option>
                {subnets.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.network} {s.name && `(${s.name})`}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div>
            <label className="block text-xs font-medium">External IP</label>
            <input
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-sm"
              value={externalIp}
              onChange={(e) => setExternalIp(e.target.value)}
              placeholder="203.0.113.5"
            />
          </div>
        </div>

        {showPorts && (
          <>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-xs font-medium">
                  Internal port start
                </label>
                <input
                  type="number"
                  min={0}
                  max={65535}
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
                  value={internalPortStart}
                  onChange={(e) => setInternalPortStart(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium">
                  Internal port end
                </label>
                <input
                  type="number"
                  min={0}
                  max={65535}
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
                  value={internalPortEnd}
                  onChange={(e) => setInternalPortEnd(e.target.value)}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-xs font-medium">
                  External port start
                </label>
                <input
                  type="number"
                  min={0}
                  max={65535}
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
                  value={externalPortStart}
                  onChange={(e) => setExternalPortStart(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium">
                  External port end
                </label>
                <input
                  type="number"
                  min={0}
                  max={65535}
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
                  value={externalPortEnd}
                  onChange={(e) => setExternalPortEnd(e.target.value)}
                />
              </div>
            </div>
          </>
        )}

        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <div>
            <label className="block text-xs font-medium">Protocol</label>
            <select
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as NATProtocol)}
            >
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium">
              Device label (free text)
            </label>
            <input
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
              value={deviceLabel}
              onChange={(e) => setDeviceLabel(e.target.value)}
              placeholder="firewall-01"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium">Description</label>
          <textarea
            className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
          />
        </div>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────

export function NATPage() {
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'nat_mapping'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "nat_mapping"),
    "Requires write permission on NAT mappings",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "nat_mapping"),
    "Requires delete permission on NAT mappings",
  );
  const qc = useQueryClient();
  // #2100 — NAT mappings are the ``ipam.nat`` feature module. Reached by a
  // bookmark while it is off, or left open after deleting the LAST mapping
  // on an install that never set the toggle (with no override the module is
  // on only while ``nat_mapping`` holds a row), the page says so instead of
  // firing requests the router answers 404.
  const modules = useFeatureModules();
  const natOn = modules.ready && modules.enabled("ipam.nat");
  const natOff = modules.ready && !modules.enabled("ipam.nat");
  const [kindFilter, setKindFilter] = useState<NATKind | "">("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const perPage = 50;
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<NATMapping | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<NATMapping | null>(null);

  const params = useMemo(
    () => ({
      kind: kindFilter || undefined,
      q: search || undefined,
      page,
      per_page: perPage,
    }),
    [kindFilter, search, page],
  );

  const { data, isLoading } = useQuery({
    queryKey: ["nat-mappings", params],
    queryFn: () => natApi.list(params),
    placeholderData: (prev) => prev,
    enabled: natOn,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => natApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["nat-mappings"] });
      // Deleting the last mapping can turn the module off (#2100); re-read
      // the module set so the sidebar and this page follow the router.
      qc.invalidateQueries({ queryKey: ["feature-modules"] });
      setConfirmDelete(null);
    },
  });

  function refresh() {
    qc.invalidateQueries({ queryKey: ["nat-mappings"] });
  }

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  if (natOff) {
    return (
      <div className="h-full overflow-auto p-6">
        <h1 className="text-2xl font-bold tracking-tight">NAT mappings</h1>
        <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
          NAT mappings are turned off. Any existing mappings are kept, and the
          firewall mirrors keep recording NAT rules while the feature is off.
          With no explicit setting, NAT mappings are on only while at least one
          mapping exists, so deleting the last one turns them off. An
          administrator can turn them on under{" "}
          <Link to="/admin/features" className="text-primary hover:underline">
            Features & Integrations
          </Link>
          .
        </p>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-2xl font-bold tracking-tight">NAT mappings</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Operator-curated 1:1 / PAT / hide-NAT records. SpatiumDDI does not
              push the rules — these are visibility metadata so IPAM rows can
              show whether an address is one side of a known mapping.
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex flex-shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Plus className="h-3.5 w-3.5" />
            New mapping
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            className="rounded-md border bg-background px-2 py-1 text-xs"
            value={kindFilter}
            onChange={(e) => {
              setKindFilter(e.target.value as NATKind | "");
              setPage(1);
            }}
          >
            <option value="">All kinds</option>
            <option value="1to1">1:1 NAT</option>
            <option value="pat">PAT</option>
            <option value="hide">Hide / Masquerade</option>
          </select>
          <input
            className="rounded-md border bg-background px-2 py-1 text-xs"
            placeholder="Search name / description"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="rounded-lg border bg-card overflow-auto">
          {isLoading ? (
            <p className="px-4 py-6 text-sm text-muted-foreground">Loading…</p>
          ) : items.length === 0 ? (
            <p className="px-4 py-6 text-sm text-muted-foreground">
              No NAT mappings match the current filters.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Kind</th>
                  <th className="px-3 py-2">Internal</th>
                  <th className="px-3 py-2">External</th>
                  <th className="px-3 py-2">Proto</th>
                  <th className="px-3 py-2">Device</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {items.map((m) => (
                  <tr key={m.id} className="border-b last:border-0">
                    <td className="px-3 py-2">
                      <div className="font-medium">{m.name}</div>
                      {m.description && (
                        <div
                          className="truncate text-xs text-muted-foreground"
                          title={m.description}
                        >
                          {m.description}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      <span
                        className={cn(
                          "rounded-full px-2 py-0.5",
                          m.kind === "1to1"
                            ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400"
                            : m.kind === "pat"
                              ? "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-400"
                              : "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
                        )}
                      >
                        {KIND_LABEL[m.kind]}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {m.kind === "hide" ? (
                        <span className="text-muted-foreground">
                          {m.internal_subnet_cidr ??
                            m.internal_subnet_name ??
                            (m.internal_subnet_id
                              ? `subnet ${m.internal_subnet_id.slice(0, 8)}…`
                              : "—")}
                        </span>
                      ) : (
                        (m.internal_ip ?? "—")
                      )}
                      {m.kind === "pat" && (
                        <span className="ml-1 text-muted-foreground">
                          :
                          {pickPort(m.internal_port_start, m.internal_port_end)}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {m.external_ip ?? "—"}
                      {m.kind === "pat" && (
                        <span className="ml-1 text-muted-foreground">
                          :
                          {pickPort(m.external_port_start, m.external_port_end)}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">{m.protocol}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {m.device_label ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-1">
                        <button
                          onClick={() => setEditing(m)}
                          className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                          title="Edit"
                          {...writeGate}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setConfirmDelete(m)}
                          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                          title="Delete"
                          {...deleteGate}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {total > 0 && (
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              {total} mapping{total === 1 ? "" : "s"} • page {page} /{" "}
              {totalPages}
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

      {showCreate && (
        <NATMappingModal
          initial={null}
          onClose={() => setShowCreate(false)}
          onSaved={refresh}
        />
      )}
      {editing && (
        <NATMappingModal
          initial={editing}
          onClose={() => setEditing(null)}
          onSaved={refresh}
        />
      )}
      {confirmDelete && (
        <Modal
          title="Delete NAT mapping?"
          onClose={() => setConfirmDelete(null)}
        >
          <div className="space-y-3 p-4">
            <p className="text-sm">
              Delete NAT mapping{" "}
              <span className="font-medium">{confirmDelete.name}</span>? This
              cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmDelete(null)}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMut.mutate(confirmDelete.id)}
                disabled={deleteMut.isPending}
                className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                Delete
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

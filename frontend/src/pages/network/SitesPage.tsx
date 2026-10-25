import { ListEmpty } from "@/components/ui/list-read-error";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  DndContext,
  PointerSensor,
  useSensor,
  useSensors,
  useDraggable,
  useDroppable,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import {
  ChevronRight,
  CornerLeftUp,
  GripVertical,
  ListTree,
  Move,
  Pencil,
  Plus,
  RefreshCw,
  Table as TableIcon,
  Trash2,
} from "lucide-react";
import {
  sitesApi,
  type SiteCreate,
  type SiteKind,
  type SiteRead,
  type SiteUpdate,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { useSessionState } from "@/lib/useSessionState";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ServicesUsingButton } from "@/components/ServicesUsingButton";
import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// A site can never be re-parented under itself or any of its own
// descendants (that would form a cycle). Returns the blocked set: the
// root site id + every transitive child. Shared by the editor parent
// picker, the Move modal, and the tree drag-and-drop drop-target gate
// (issue #279 — the backend enforces the same rule in _validate_parent).
function descendantSet(sites: SiteRead[], rootId: string): Set<string> {
  const blocked = new Set<string>([rootId]);
  let added = true;
  while (added) {
    added = false;
    for (const s of sites) {
      if (
        !blocked.has(s.id) &&
        s.parent_site_id &&
        blocked.has(s.parent_site_id)
      ) {
        blocked.add(s.id);
        added = true;
      }
    }
  }
  return blocked;
}

const KINDS: SiteKind[] = [
  "datacenter",
  "branch",
  "pop",
  "colo",
  "cloud_region",
  "customer_premise",
];

const KIND_LABELS: Record<SiteKind, string> = {
  datacenter: "Datacenter",
  branch: "Branch",
  pop: "PoP",
  colo: "Colo",
  cloud_region: "Cloud region",
  customer_premise: "Customer premise",
};

function SiteEditorModal({
  existing,
  sites,
  onClose,
}: {
  existing: SiteRead | null;
  sites: SiteRead[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [code, setCode] = useState(existing?.code ?? "");
  const [kind, setKind] = useState<SiteKind>(existing?.kind ?? "datacenter");
  const [region, setRegion] = useState(existing?.region ?? "");
  const [parentId, setParentId] = useState(existing?.parent_site_id ?? "");
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  // Self + descendants are illegal parent picks (would form a cycle).
  const cycleBlockedIds = useMemo(
    () => (existing ? descendantSet(sites, existing.id) : new Set<string>()),
    [existing, sites],
  );

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      if (existing) {
        const body: SiteUpdate = {
          name,
          code: code || null,
          kind,
          region: region || null,
          parent_site_id: parentId || null,
          notes,
        };
        return sitesApi.update(existing.id, body);
      }
      const body: SiteCreate = {
        name,
        code: code || null,
        kind,
        region: region || null,
        parent_site_id: parentId || null,
        notes,
      };
      return sitesApi.create(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sites"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Save failed");
    },
  });

  return (
    <Modal onClose={onClose} title={existing ? "Edit site" : "New site"} wide>
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1 sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Name
            </label>
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus={!existing}
              placeholder="NYC East Datacenter"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Code
            </label>
            <input
              className={inputCls}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="DC-EAST"
            />
            <p className="text-[11px] text-muted-foreground/80">
              Unique within a parent. Use in CLI / runbooks.
            </p>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Kind
            </label>
            <select
              className={inputCls}
              value={kind}
              onChange={(e) => setKind(e.target.value as SiteKind)}
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Region
            </label>
            <input
              className={inputCls}
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              placeholder="us-east-1 / EMEA / NYC metro"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Parent site
            </label>
            <select
              className={inputCls}
              value={parentId}
              onChange={(e) => setParentId(e.target.value)}
            >
              <option value="">— none —</option>
              {sites
                .filter((s) => !cycleBlockedIds.has(s.id))
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                    {s.code ? ` (${s.code})` : ""}
                  </option>
                ))}
            </select>
          </div>
          <div className="space-y-1 sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Notes
            </label>
            <textarea
              className={cn(inputCls, "min-h-[80px]")}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={mut.isPending}
            onClick={() => mut.mutate()}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Move modal ──────────────────────────────────────────────────────
// Keyboard / touch-friendly re-parent (issue #279 Option B): a search
// box over the valid parent sites (self + descendants excluded via the
// shared descendantSet) plus a "Make top-level" action. Complements the
// tree's drag-and-drop for large trees where precise drops are fiddly.
function MoveSiteModal({
  site,
  sites,
  onClose,
}: {
  site: SiteRead;
  sites: SiteRead[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);

  const blocked = useMemo(
    () => descendantSet(sites, site.id),
    [sites, site.id],
  );
  const options = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return sites
      .filter((s) => !blocked.has(s.id))
      .filter(
        (s) =>
          !needle ||
          s.name.toLowerCase().includes(needle) ||
          (s.code ?? "").toLowerCase().includes(needle),
      )
      .sort((a, b) =>
        a.name.localeCompare(b.name, undefined, {
          numeric: true,
          sensitivity: "base",
        }),
      );
  }, [sites, blocked, q]);

  const currentParentName = site.parent_site_id
    ? (sites.find((s) => s.id === site.parent_site_id)?.name ?? "—")
    : null;

  const mut = useMutation({
    mutationFn: (parentId: string | null) =>
      sitesApi.update(site.id, { parent_site_id: parentId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sites"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Move failed");
    },
  });

  return (
    <Modal onClose={onClose} title={`Move “${site.name}”`}>
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Current parent:{" "}
          <span className="font-medium text-foreground">
            {currentParentName ?? "top-level (no parent)"}
          </span>
        </p>
        <button
          type="button"
          disabled={!site.parent_site_id || mut.isPending}
          onClick={() => mut.mutate(null)}
          className="flex w-full items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-muted disabled:opacity-40"
        >
          <CornerLeftUp className="h-4 w-4" />
          Make top-level (no parent)
        </button>
        <input
          className={inputCls}
          placeholder="Search sites by name / code…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          autoFocus
        />
        <div className="max-h-64 divide-y overflow-y-auto rounded-md border">
          {options.length === 0 && (
            <p className="px-3 py-4 text-center text-sm text-muted-foreground">
              No eligible parent sites.
            </p>
          )}
          {options.map((s) => (
            <button
              key={s.id}
              type="button"
              disabled={mut.isPending || s.id === site.parent_site_id}
              onClick={() => mut.mutate(s.id)}
              className={cn(
                "flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-muted disabled:opacity-40",
                s.id === site.parent_site_id && "bg-muted/50",
              )}
            >
              <span className="break-words font-medium">{s.name}</span>
              <span className="ml-2 shrink-0 text-xs text-muted-foreground">
                {s.code ? `${s.code} · ` : ""}
                {KIND_LABELS[s.kind]}
                {s.id === site.parent_site_id ? " · current" : ""}
              </span>
            </button>
          ))}
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
      </div>
    </Modal>
  );
}

// ── Tree view ───────────────────────────────────────────────────────
const ROOT_DROP_ID = "__site_root__";

function RootDropZone({ active }: { active: boolean }) {
  const { setNodeRef, isOver } = useDroppable({ id: ROOT_DROP_ID });
  if (!active) return null;
  return (
    <div
      ref={setNodeRef}
      className={cn(
        "mb-2 rounded-md border border-dashed px-3 py-2 text-center text-xs text-muted-foreground transition-colors",
        isOver
          ? "border-primary bg-primary/10 text-primary"
          : "border-muted-foreground/40",
      )}
    >
      Drop here to make top-level
    </div>
  );
}

function SiteTreeRow({
  site,
  depth,
  childrenByParent,
  expanded,
  toggleExpand,
  activeId,
  blockedForActive,
  onEdit,
  onMove,
  onDelete,
}: {
  site: SiteRead;
  depth: number;
  childrenByParent: Map<string | null, SiteRead[]>;
  expanded: Set<string>;
  toggleExpand: (id: string) => void;
  activeId: string | null;
  blockedForActive: Set<string>;
  onEdit: (s: SiteRead) => void;
  onMove: (s: SiteRead) => void;
  onDelete: (s: SiteRead) => void;
}) {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'site'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "site"),
    "Requires write permission on sites",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "site"),
    "Requires delete permission on sites",
  );
  const kids = childrenByParent.get(site.id) ?? [];
  const hasKids = kids.length > 0;
  const isExpanded = expanded.has(site.id);
  // While a drag is in flight, the dragged site + its descendants can't
  // accept the drop (cycle) — disable + dim them.
  const isBlocked = activeId !== null && blockedForActive.has(site.id);
  const isSelf = activeId === site.id;

  const {
    attributes,
    listeners,
    setNodeRef: dragRef,
    isDragging,
  } = useDraggable({ id: site.id, disabled: !perms.can("write", "site") });
  const { setNodeRef: dropRef, isOver } = useDroppable({
    id: site.id,
    disabled: isBlocked,
  });
  const setRefs = (node: HTMLElement | null) => {
    dragRef(node);
    dropRef(node);
  };

  return (
    <>
      <div
        ref={setRefs}
        style={{ paddingLeft: depth * 20 + 8 }}
        className={cn(
          "flex items-center gap-1.5 py-1.5 pr-2 transition-colors",
          isOver &&
            !isBlocked &&
            "bg-primary/10 ring-1 ring-inset ring-primary/40",
          isBlocked && "opacity-40",
          isDragging && "opacity-50",
        )}
      >
        <button
          ref={dragRef}
          {...listeners}
          {...attributes}
          title="Drag to re-parent"
          className="cursor-grab rounded p-0.5 text-muted-foreground/60 hover:bg-muted hover:text-foreground active:cursor-grabbing disabled:cursor-not-allowed disabled:opacity-40"
          // Dropping re-parents the site: a PUT the router asks write on
          // 'site' for, the same as the Move button.
          {...writeGate}
        >
          <GripVertical className="h-3.5 w-3.5" />
        </button>
        {hasKids ? (
          <button
            type="button"
            onClick={() => toggleExpand(site.id)}
            className="rounded p-0.5 hover:bg-muted"
            title={isExpanded ? "Collapse" : "Expand"}
          >
            <ChevronRight
              className={cn(
                "h-3.5 w-3.5 transition-transform",
                isExpanded && "rotate-90",
              )}
            />
          </button>
        ) : (
          <span className="inline-block w-[18px]" />
        )}
        <span className="break-words font-medium">{site.name}</span>
        {site.code && (
          <span className="rounded border px-1 py-0.5 text-[10px] text-muted-foreground tabular-nums">
            {site.code}
          </span>
        )}
        <span className="text-xs text-muted-foreground">
          {KIND_LABELS[site.kind]}
        </span>
        {site.region && (
          <span className="text-xs text-muted-foreground/70">
            · {site.region}
          </span>
        )}
        <div className="ml-auto flex items-center">
          <ServicesUsingButton
            kind="site"
            resourceId={site.id}
            label={site.name}
            compact
          />
          <button
            type="button"
            title="Move"
            onClick={() => onMove(site)}
            className="ml-1 rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Move className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            title="Edit"
            onClick={() => onEdit(site)}
            className="ml-1 rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            title="Delete"
            onClick={() => onDelete(site)}
            className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
            {...deleteGate}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      {hasKids &&
        isExpanded &&
        !isSelf &&
        kids.map((k) => (
          <SiteTreeRow
            key={k.id}
            site={k}
            depth={depth + 1}
            childrenByParent={childrenByParent}
            expanded={expanded}
            toggleExpand={toggleExpand}
            activeId={activeId}
            blockedForActive={blockedForActive}
            onEdit={onEdit}
            onMove={onMove}
            onDelete={onDelete}
          />
        ))}
    </>
  );
}

function SiteTreeView({
  sites,
  onEdit,
  onMove,
  onDelete,
}: {
  sites: SiteRead[];
  onEdit: (s: SiteRead) => void;
  onMove: (s: SiteRead) => void;
  onDelete: (s: SiteRead) => void;
}) {
  const qc = useQueryClient();
  const [activeId, setActiveId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Expand everything by default so the hierarchy is visible at a glance;
  // operators collapse what they don't care about.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
  );

  const childrenByParent = useMemo(() => {
    const ids = new Set(sites.map((s) => s.id));
    const m = new Map<string | null, SiteRead[]>();
    for (const s of sites) {
      // A parent_site_id pointing outside the current list (e.g. filtered
      // out) is treated as a root so the row never vanishes.
      const key =
        s.parent_site_id && ids.has(s.parent_site_id) ? s.parent_site_id : null;
      const arr = m.get(key) ?? [];
      arr.push(s);
      m.set(key, arr);
    }
    for (const arr of m.values()) {
      arr.sort((a, b) =>
        a.name.localeCompare(b.name, undefined, {
          numeric: true,
          sensitivity: "base",
        }),
      );
    }
    return m;
  }, [sites]);

  const blockedForActive = useMemo(
    () => (activeId ? descendantSet(sites, activeId) : new Set<string>()),
    [activeId, sites],
  );
  const expanded = useMemo(() => {
    // expanded = everything except the collapsed set.
    const all = new Set(sites.map((s) => s.id));
    for (const id of collapsed) all.delete(id);
    return all;
  }, [sites, collapsed]);

  const reparent = useMutation({
    mutationFn: ({ id, parentId }: { id: string; parentId: string | null }) =>
      sitesApi.update(id, { parent_site_id: parentId }),
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Move failed");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["sites"] }),
  });

  function toggleExpand(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function handleDragStart(e: DragStartEvent) {
    setError(null);
    setActiveId(String(e.active.id));
  }

  function handleDragEnd(e: DragEndEvent) {
    const draggedId = String(e.active.id);
    setActiveId(null);
    if (!e.over) return;
    const overId = String(e.over.id);
    const newParent = overId === ROOT_DROP_ID ? null : overId;
    const dragged = sites.find((s) => s.id === draggedId);
    if (!dragged) return;
    if ((dragged.parent_site_id ?? null) === newParent) return; // no-op drop
    // Cycle guard mirrors the backend's _validate_parent.
    if (newParent && descendantSet(sites, draggedId).has(newParent)) return;
    reparent.mutate({ id: draggedId, parentId: newParent });
  }

  const roots = childrenByParent.get(null) ?? [];

  return (
    <div className="space-y-2">
      {error && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        Drag the <GripVertical className="inline h-3 w-3" /> handle onto another
        site to re-parent, or use the <Move className="inline h-3 w-3" /> Move
        button. Drop on the zone above to make a site top-level.
      </p>
      <DndContext
        sensors={sensors}
        onDragStart={handleDragStart}
        onDragEnd={handleDragEnd}
        onDragCancel={() => setActiveId(null)}
      >
        <RootDropZone active={activeId !== null} />
        <div className="divide-y rounded-lg border text-sm">
          {roots.length === 0 ? (
            <p className="px-3 py-6 text-center text-muted-foreground">
              No sites yet — click “New site” to add one.
            </p>
          ) : (
            roots.map((s) => (
              <SiteTreeRow
                key={s.id}
                site={s}
                depth={0}
                childrenByParent={childrenByParent}
                expanded={expanded}
                toggleExpand={toggleExpand}
                activeId={activeId}
                blockedForActive={blockedForActive}
                onEdit={onEdit}
                onMove={onMove}
                onDelete={onDelete}
              />
            ))
          )}
        </div>
      </DndContext>
    </div>
  );
}

export function SitesPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'site'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "site"),
    "Requires write permission on sites",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "site"),
    "Requires delete permission on sites",
  );
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState<SiteKind | "">("");
  const [editing, setEditing] = useState<SiteRead | null>(null);
  const [moving, setMoving] = useState<SiteRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  // Tree is the primary view per #279 (hierarchy at a glance + drag-to-
  // reparent); the flat table stays one click away via the toggle.
  const [view, setView] = useSessionState<"table" | "tree">(
    "sites.view",
    "tree",
  );
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);

  const query = useQuery({
    queryKey: ["sites", search, kindFilter],
    queryFn: () =>
      sitesApi.list({
        limit: 500,
        search: search || undefined,
        kind: (kindFilter || undefined) as SiteKind | undefined,
      }),
  });

  // Saved-views payload (#77) — the page's filter + layout state.
  type SitesViewPayload = {
    search: string;
    kind: SiteKind | "";
    view: "table" | "tree";
  };
  const viewPayload: SitesViewPayload = { search, kind: kindFilter, view };
  function applyView(p: SitesViewPayload) {
    setSearch(typeof p.search === "string" ? p.search : "");
    setKindFilter((p.kind ?? "") as SiteKind | "");
    if (p.view === "table" || p.view === "tree") setView(p.view);
  }

  // For the parent picker — a separate fetch so that filter changes
  // on the table don't shrink the picker's options.
  const allSitesQuery = useQuery({
    queryKey: ["sites", "all"],
    queryFn: () => sitesApi.list({ limit: 500 }),
  });

  const items = query.data?.items ?? [];
  const allSites = allSitesQuery.data?.items ?? [];
  const siteName = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of allSites) m.set(s.id, s.name);
    return m;
  }, [allSites]);

  const allChecked = useMemo(
    () => items.length > 0 && items.every((c) => selectedIds.has(c.id)),
    [items, selectedIds],
  );

  // A delete can be refused (409) while an E911 site-default binding
  // points at the site (#2298); show the server's reason, don't swallow it.
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const onDeleteError = (e: unknown) => {
    const err = e as {
      response?: { data?: { detail?: string } };
      message?: string;
    };
    setDeleteError(
      err?.response?.data?.detail ?? err?.message ?? "Delete failed",
    );
  };

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => sitesApi.bulkDelete(ids),
    onMutate: () => setDeleteError(null),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["sites"] });
    },
    onError: onDeleteError,
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => sitesApi.remove(id),
    onMutate: () => setDeleteError(null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sites"] }),
    onError: onDeleteError,
  });

  function toggle(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (allChecked) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((c) => c.id)));
    }
  }

  function askDelete(s: SiteRead) {
    setConfirm({
      title: "Delete site",
      message: `Delete site "${s.name}"? A site that still has an E911 site-default binding cannot be deleted until that binding is removed.`,
      confirmLabel: "Delete",
      onConfirm: () => removeOne.mutate(s.id),
    });
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        {deleteError && (
          <p role="alert" className="text-sm text-destructive">
            {deleteError}
          </p>
        )}
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold">Sites</h1>
            <p className="text-sm text-muted-foreground">
              Physical locations resources are deployed at. Hierarchical: a
              campus site can have building / floor sites under it. Distinct
              from CMDB — no rack / U / floor-plan tracking.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <div className="inline-flex overflow-hidden rounded-md border text-sm">
              <button
                type="button"
                onClick={() => setView("table")}
                className={cn(
                  "inline-flex items-center gap-1.5 px-2.5 py-1.5",
                  view === "table"
                    ? "bg-muted font-medium"
                    : "text-muted-foreground hover:bg-muted/50",
                )}
                title="Flat table"
              >
                <TableIcon className="h-3.5 w-3.5" />
                Table
              </button>
              <button
                type="button"
                onClick={() => setView("tree")}
                className={cn(
                  "inline-flex items-center gap-1.5 border-l px-2.5 py-1.5",
                  view === "tree"
                    ? "bg-muted font-medium"
                    : "text-muted-foreground hover:bg-muted/50",
                )}
                title="Hierarchy tree (drag to re-parent)"
              >
                <ListTree className="h-3.5 w-3.5" />
                Tree
              </button>
            </div>
            <SavedViewsMenu
              page="network.sites"
              currentPayload={viewPayload}
              onApply={applyView}
            />
            <HeaderButton
              icon={RefreshCw}
              onClick={() => query.refetch()}
              iconClassName={query.isFetching ? "animate-spin" : undefined}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowNew(true)}
              {...writeGate}
            >
              New site
            </HeaderButton>
          </div>
        </div>

        {view === "table" && (
          <div className="flex flex-wrap items-center gap-2">
            <input
              className={cn(inputCls, "max-w-xs")}
              placeholder="Search name / code / region…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select
              className={cn(inputCls, "max-w-[180px]")}
              value={kindFilter}
              onChange={(e) => setKindFilter(e.target.value as SiteKind | "")}
            >
              <option value="">All kinds</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
          </div>
        )}

        {view === "table" && selectedIds.size > 0 && (
          <div className="flex items-center justify-between rounded-md border bg-muted/50 px-3 py-2 text-sm">
            <span>{selectedIds.size} selected</span>
            <HeaderButton
              variant="destructive"
              icon={Trash2}
              disabled={bulkDelete.isPending}
              onClick={() => {
                const ids = Array.from(selectedIds);
                setConfirm({
                  title: "Delete sites",
                  message: `Delete ${ids.length} site${ids.length === 1 ? "" : "s"}?`,
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

        {view === "tree" ? (
          allSitesQuery.isLoading ? (
            <div className="rounded-lg border px-3 py-6 text-center text-sm text-muted-foreground">
              Loading…
            </div>
          ) : (
            <SiteTreeView
              sites={allSites}
              onEdit={(s) => setEditing(s)}
              onMove={(s) => setMoving(s)}
              onDelete={askDelete}
            />
          )
        ) : (
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="w-8 px-3 py-2">
                    <input
                      type="checkbox"
                      checked={allChecked}
                      onChange={toggleAll}
                      aria-label="Select all"
                    />
                  </th>
                  <th className="px-3 py-2 text-left">Name</th>
                  <th className="px-3 py-2 text-left">Code</th>
                  <th className="px-3 py-2 text-left">Kind</th>
                  <th className="px-3 py-2 text-left">Region</th>
                  <th className="px-3 py-2 text-left">Parent</th>
                  <th className="w-24 px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {query.isLoading && (
                  <tr>
                    <td
                      className="px-3 py-6 text-center text-muted-foreground"
                      colSpan={7}
                    >
                      Loading…
                    </td>
                  </tr>
                )}
                {!query.isLoading && items.length === 0 && (
                  <tr>
                    <td
                      className="px-3 py-6 text-center text-muted-foreground"
                      colSpan={7}
                    >
                      <ListEmpty
                        error={query.error}
                        what="sites"
                        filtered={search !== "" || kindFilter !== ""}
                        onClearFilters={() => {
                          setSearch("");
                          setKindFilter("");
                        }}
                      >
                        No sites yet — click "New site" to add one.
                      </ListEmpty>
                    </td>
                  </tr>
                )}
                {items.map((s) => (
                  <tr key={s.id} className="border-t">
                    <td className="px-3 py-2 align-top">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(s.id)}
                        onChange={() => toggle(s.id)}
                      />
                    </td>
                    <td className="px-3 py-2 align-top break-words font-medium">
                      {s.name}
                    </td>
                    <td className="px-3 py-2 align-top break-all text-muted-foreground tabular-nums">
                      {s.code ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top text-muted-foreground">
                      {KIND_LABELS[s.kind]}
                    </td>
                    <td className="px-3 py-2 align-top break-words text-muted-foreground">
                      {s.region ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top break-words text-muted-foreground">
                      {s.parent_site_id
                        ? (siteName.get(s.parent_site_id) ?? "—")
                        : "—"}
                    </td>
                    <td className="px-3 py-2 align-top text-right">
                      <button
                        type="button"
                        title="Move"
                        onClick={() => setMoving(s)}
                        className="rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                        {...writeGate}
                      >
                        <Move className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        title="Edit"
                        onClick={() => setEditing(s)}
                        className="ml-1 rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                        {...writeGate}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        title="Delete"
                        onClick={() => askDelete(s)}
                        className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
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
        )}

        {showNew && (
          <SiteEditorModal
            existing={null}
            sites={allSites}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <SiteEditorModal
            existing={editing}
            sites={allSites}
            onClose={() => setEditing(null)}
          />
        )}
        {moving && (
          <MoveSiteModal
            site={moving}
            sites={allSites}
            onClose={() => setMoving(null)}
          />
        )}
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
      </div>
    </div>
  );
}

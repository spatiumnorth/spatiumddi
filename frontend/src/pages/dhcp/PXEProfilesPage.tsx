/**
 * PXE / iPXE profiles management page (issue #51).
 *
 * Mounted at /dhcp/groups/:groupId/pxe. List + simple editor with
 * arch-match rows. Priority is a number input (lower = higher
 * priority); operators bump it manually rather than drag-reorder
 * — keeps the editor compact for the typical 2-4 match profiles.
 *
 * Profiles bind to scopes via ``DHCPScope.pxe_profile_id`` (set
 * from the Scope edit modal). Disabled profiles render no Kea
 * client-classes.
 */

import {
  Children,
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useState,
} from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Pencil, Plus, Trash2, X, Loader2 } from "lucide-react";
import {
  dhcpApi,
  DHCP_PXE_ARCH_LABELS,
  type PXEArchMatchInput,
  type PXEMatchKind,
  type PXEProfile,
  type PXEProfileCreate,
  type PXEProfileUpdate,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// #1861 — PXE profiles ride on ``dhcp_scope`` (pxe_profiles.py): writes take
// write and a delete takes delete. A read-only user is offered none of them.
const NEEDS_PXE_WRITE = "Requires write permission on DHCP scopes";
const NEEDS_PXE_DELETE = "Requires delete permission on DHCP scopes";

export function PXEProfilesPage() {
  const { groupId = "" } = useParams<{ groupId: string }>();
  const qc = useQueryClient();
  const perms = usePermissions();
  const [editing, setEditing] = useState<PXEProfile | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<PXEProfile | null>(null);

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ["dhcp-pxe-profiles", groupId],
    queryFn: () => dhcpApi.listPxeProfiles(groupId),
    enabled: !!groupId,
  });

  const { data: group } = useQuery({
    queryKey: ["dhcp-group", groupId],
    queryFn: () => dhcpApi.getGroup(groupId),
    enabled: !!groupId,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deletePxeProfile(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-pxe-profiles", groupId] });
      setDeleting(null);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <Link
          to="/dhcp"
          className="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" /> Back to DHCP
        </Link>
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">PXE / iPXE profiles</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Reusable PXE provisioning profiles for{" "}
              <strong>{group?.name ?? groupId}</strong>. Each profile bundles a
              TFTP / HTTP boot server + per-arch matches; bind a profile to a
              scope from the Scope edit modal.
            </p>
          </div>
          <button
            onClick={() => setCreating(true)}
            className="inline-flex flex-shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            {...permissionGate(
              perms.can("write", "dhcp_scope"),
              NEEDS_PXE_WRITE,
            )}
          >
            <Plus className="h-3.5 w-3.5" />
            New profile
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {isLoading ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
          </div>
        ) : profiles.length === 0 ? (
          <div className="rounded-lg border bg-card p-8 text-center">
            <p className="text-sm text-muted-foreground">
              No PXE profiles yet for this group.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {profiles.map((p) => (
              <ProfileCard
                key={p.id}
                profile={p}
                onEdit={() => setEditing(p)}
                onDelete={() => setDeleting(p)}
              />
            ))}
          </div>
        )}
      </div>

      {creating && (
        <ProfileEditor
          mode="create"
          groupId={groupId}
          onClose={() => setCreating(false)}
          onSaved={() => {
            qc.invalidateQueries({ queryKey: ["dhcp-pxe-profiles", groupId] });
            setCreating(false);
          }}
        />
      )}
      {editing && (
        <ProfileEditor
          mode="edit"
          groupId={groupId}
          existing={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            qc.invalidateQueries({ queryKey: ["dhcp-pxe-profiles", groupId] });
            setEditing(null);
          }}
        />
      )}
      {deleting && (
        <Modal title="Delete PXE profile" onClose={() => setDeleting(null)}>
          <div className="space-y-4 text-sm">
            <p>
              Permanently delete <strong>{deleting.name}</strong>? Any scope
              currently bound to this profile will detach automatically (FK SET
              NULL).
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleting(null)}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMut.mutate(deleting.id)}
                disabled={deleteMut.isPending}
                className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {deleteMut.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function ProfileCard({
  profile,
  onEdit,
  onDelete,
}: {
  profile: PXEProfile;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const perms = usePermissions();
  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold">{profile.name}</span>
          <span
            className={
              profile.enabled
                ? "rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-300"
                : "rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
            }
          >
            {profile.enabled ? "Enabled" : "Disabled"}
          </span>
        </div>
        <div className="flex gap-1">
          <button
            onClick={onEdit}
            className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-40"
            title="Edit"
            {...permissionGate(
              perms.can("write", "dhcp_scope"),
              NEEDS_PXE_WRITE,
            )}
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={onDelete}
            className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:opacity-40"
            title="Delete"
            {...permissionGate(
              perms.can("delete", "dhcp_scope"),
              NEEDS_PXE_DELETE,
            )}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      <div className="space-y-2 p-4 text-xs">
        {profile.description && (
          <p className="text-muted-foreground">{profile.description}</p>
        )}
        <p>
          <span className="text-muted-foreground">next-server:</span>{" "}
          <code className="font-mono">{profile.next_server}</code>
        </p>
        {profile.matches.length === 0 ? (
          <p className="text-muted-foreground">
            No arch-matches — profile renders no client-classes.
          </p>
        ) : (
          <table className="w-full font-mono text-[11px]">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="pr-2">Pri</th>
                <th className="pr-2">Kind</th>
                <th className="pr-2">Vendor class</th>
                <th className="pr-2">Arch</th>
                <th>Boot file</th>
              </tr>
            </thead>
            <tbody>
              {profile.matches.map((m) => (
                <tr key={m.id} className="border-t">
                  <td className="pr-2">{m.priority}</td>
                  <td className="pr-2">{m.match_kind}</td>
                  <td className="pr-2">{m.vendor_class_match ?? "(any)"}</td>
                  <td className="pr-2">
                    {m.arch_codes && m.arch_codes.length > 0
                      ? m.arch_codes.join(",")
                      : "(any)"}
                  </td>
                  <td className="break-all">{m.boot_filename}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export function ProfileEditor({
  mode,
  groupId,
  existing,
  onClose,
  onSaved,
}: {
  mode: "create" | "edit";
  groupId: string;
  existing?: PXEProfile;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [nextServer, setNextServer] = useState(existing?.next_server ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [matches, setMatches] = useState<PXEArchMatchInput[]>(
    () =>
      existing?.matches.map((m) => ({
        priority: m.priority,
        match_kind: m.match_kind,
        vendor_class_match: m.vendor_class_match,
        arch_codes: m.arch_codes,
        boot_filename: m.boot_filename,
        boot_file_url_v6: m.boot_file_url_v6,
      })) ?? [],
  );
  const [error, setError] = useState<string | null>(null);

  // Empty-form helper — when creating a fresh profile with no matches,
  // seed two stub rows (BIOS + UEFI x86-64) so the operator sees the
  // typical pattern. Doesn't touch when editing an existing profile.
  useEffect(() => {
    if (mode === "create" && matches.length === 0) {
      setMatches([
        {
          priority: 10,
          match_kind: "first_stage",
          vendor_class_match: "PXEClient",
          arch_codes: [0],
          boot_filename: "undionly.kpxe",
        },
        {
          priority: 20,
          match_kind: "first_stage",
          vendor_class_match: "PXEClient",
          arch_codes: [7, 9],
          boot_filename: "ipxe.efi",
        },
      ]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  const mut = useMutation({
    mutationFn: () => {
      const sanitized = matches.map((m) => ({
        priority: m.priority ?? 100,
        match_kind: m.match_kind ?? "first_stage",
        vendor_class_match:
          m.vendor_class_match && m.vendor_class_match.trim()
            ? m.vendor_class_match.trim()
            : null,
        arch_codes:
          m.arch_codes && m.arch_codes.length > 0 ? m.arch_codes : null,
        boot_filename: m.boot_filename.trim(),
        boot_file_url_v6: m.boot_file_url_v6 ?? null,
      }));
      if (mode === "create") {
        const body: PXEProfileCreate = {
          name,
          description,
          next_server: nextServer,
          enabled,
          matches: sanitized,
        };
        return dhcpApi.createPxeProfile(groupId, body);
      }
      const body: PXEProfileUpdate = {
        name,
        description,
        next_server: nextServer,
        enabled,
        matches: sanitized,
      };
      return dhcpApi.updatePxeProfile(existing!.id, body);
    },
    onSuccess: () => onSaved(),
    onError: (err: unknown) => {
      setError(formatApiError(err, "Save failed."));
    },
  });

  function patchMatch(idx: number, p: Partial<PXEArchMatchInput>) {
    setMatches((prev) => prev.map((m, i) => (i === idx ? { ...m, ...p } : m)));
  }
  function removeMatch(idx: number) {
    setMatches((prev) => prev.filter((_, i) => i !== idx));
  }
  function addMatch() {
    setMatches((prev) => [
      ...prev,
      {
        priority: (prev[prev.length - 1]?.priority ?? 0) + 10,
        match_kind: "first_stage",
        vendor_class_match: "PXEClient",
        arch_codes: null,
        boot_filename: "",
      },
    ]);
  }

  return (
    <Modal
      title={mode === "create" ? "New PXE profile" : `Edit "${existing?.name}"`}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          mut.mutate();
        }}
        className="space-y-3 text-sm"
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name">
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={inputCls}
              required
              placeholder="e.g. ubuntu-bios-and-uefi"
            />
          </Field>
          <Field label="Next-server (TFTP / HTTP boot host)">
            <input
              value={nextServer}
              onChange={(e) => setNextServer(e.target.value)}
              className={inputCls}
              required
              placeholder="10.0.0.5"
            />
          </Field>
        </div>
        <Field label="Description (optional)">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className={inputCls}
          />
        </Field>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span>
            Enabled — when off, this profile renders no Kea client-classes even
            if a scope is bound.
          </span>
        </label>

        <div className="space-y-2 border-t pt-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Arch-matches</h3>
            <button
              type="button"
              onClick={addMatch}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted"
            >
              <Plus className="h-3 w-3" /> Add match
            </button>
          </div>
          {matches.length === 0 && (
            <p className="text-xs text-muted-foreground">
              At least one match is required for the profile to fire any
              client-classes.
            </p>
          )}
          {matches.map((m, idx) => (
            <ArchMatchRow
              key={idx}
              row={m}
              index={idx}
              onChange={(p) => patchMatch(idx, p)}
              onRemove={() => removeMatch(idx)}
            />
          ))}
        </div>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!name || !nextServer || mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ArchMatchRow({
  row,
  index,
  onChange,
  onRemove,
}: {
  row: PXEArchMatchInput;
  index: number;
  onChange: (p: Partial<PXEArchMatchInput>) => void;
  onRemove: () => void;
}) {
  const n = `Match ${index + 1}`;
  return (
    <div
      role="group"
      aria-label={`Match rule ${index + 1}`}
      className="space-y-2 rounded border bg-muted/20 p-2 text-xs"
    >
      <div className="grid gap-2 sm:grid-cols-[6rem_8rem_1fr_auto]">
        <Field label="Priority" accessibleName={`${n}: Priority`}>
          <input
            type="number"
            value={row.priority ?? 100}
            onChange={(e) =>
              onChange({ priority: parseInt(e.target.value, 10) || 100 })
            }
            className={inputCls}
          />
        </Field>
        <Field label="Match kind" accessibleName={`${n}: Match kind`}>
          <select
            value={row.match_kind ?? "first_stage"}
            onChange={(e) =>
              onChange({ match_kind: e.target.value as PXEMatchKind })
            }
            className={inputCls}
          >
            <option value="first_stage">first_stage</option>
            <option value="ipxe_chain">ipxe_chain</option>
          </select>
        </Field>
        <Field
          label="Vendor class (option 60 substring)"
          accessibleName={`${n}: Vendor class (option 60 substring)`}
        >
          <input
            value={row.vendor_class_match ?? ""}
            onChange={(e) => onChange({ vendor_class_match: e.target.value })}
            className={inputCls}
            placeholder="PXEClient / iPXE / HTTPClient / (blank for any)"
          />
        </Field>
        <button
          type="button"
          onClick={onRemove}
          className="self-end rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
          title="Remove match"
          aria-label={`Remove match ${index + 1}`}
        >
          <X className="h-4 w-4" />
        </button>
      </div>
      <Field
        label="Arch codes (option 93)"
        accessibleName={`${n}: Arch codes (option 93)`}
      >
        <div className="flex flex-wrap gap-1">
          {Object.entries(DHCP_PXE_ARCH_LABELS).map(([codeStr, label]) => {
            const code = parseInt(codeStr, 10);
            const checked = (row.arch_codes ?? []).includes(code);
            return (
              <label
                key={codeStr}
                className={`inline-flex cursor-pointer items-center gap-1 rounded-md border px-1.5 py-0.5 ${
                  checked
                    ? "border-primary bg-primary/10 text-primary"
                    : "bg-background hover:bg-muted"
                }`}
              >
                <input
                  type="checkbox"
                  className="h-3 w-3"
                  aria-label={`${n}: arch ${code} · ${label}`}
                  checked={checked}
                  onChange={(e) => {
                    const cur = row.arch_codes ?? [];
                    onChange({
                      arch_codes: e.target.checked
                        ? [...cur, code].sort((a, b) => a - b)
                        : cur.filter((c) => c !== code),
                    });
                  }}
                />
                <span className="text-[10px]">
                  {code} · {label}
                </span>
              </label>
            );
          })}
        </div>
        <span className="block text-[10px] text-muted-foreground">
          Empty = match any arch (combine with vendor-class to filter).
        </span>
      </Field>
      <Field
        label="Boot filename / URL"
        accessibleName={`${n}: Boot filename / URL`}
      >
        <input
          value={row.boot_filename}
          onChange={(e) => onChange({ boot_filename: e.target.value })}
          className={inputCls}
          required
          placeholder={
            row.match_kind === "ipxe_chain"
              ? "http://boot.example/menu.ipxe"
              : "ipxe.efi or undionly.kpxe"
          }
        />
      </Field>
    </div>
  );
}

const CONTROL_TAGS = new Set(["input", "select", "textarea"]);

type ControlElement = React.ReactElement<{ id?: string }>;

function isControlElement(node: React.ReactNode): node is ControlElement {
  return (
    isValidElement(node) &&
    typeof node.type === "string" &&
    CONTROL_TAGS.has(node.type)
  );
}

/** A visible label that names its control (#2016). A lone input / select /
 *  textarea child is linked by htmlFor/id; anything else is wrapped in a
 *  role="group" labelled by the label, so "Arch codes" names the SET of
 *  checkboxes rather than being a <label> around their own labels.
 *  `accessibleName` (the row-qualified name, e.g. "Match 2: Priority") is
 *  set as aria-label so the same label in two rows names two controls. */
function Field({
  label,
  accessibleName,
  children,
}: {
  label: string;
  accessibleName?: string;
  children: React.ReactNode;
}) {
  const uid = useId();
  const controls = Children.toArray(children).filter(isControlElement);
  const control = controls.length === 1 ? controls[0] : null;
  const controlId = control ? (control.props.id ?? uid) : undefined;
  return (
    <div className="block space-y-1 text-[11px]">
      <label
        id={control ? undefined : uid}
        htmlFor={controlId}
        className="block font-medium text-muted-foreground"
      >
        {label}
      </label>
      {control ? (
        Children.map(children, (c) =>
          isControlElement(c)
            ? cloneElement(c, {
                id: controlId,
                ...(accessibleName ? { "aria-label": accessibleName } : {}),
              } as Partial<ControlElement["props"]>)
            : c,
        )
      ) : (
        <div
          role="group"
          aria-labelledby={accessibleName ? undefined : uid}
          aria-label={accessibleName}
          className="space-y-1"
        >
          {children}
        </div>
      )}
    </div>
  );
}

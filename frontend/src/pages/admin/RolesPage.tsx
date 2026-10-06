import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Pencil, Plus, Trash2 } from "lucide-react";
import {
  formatApiError,
  rolesApi,
  type AppRole,
  type PermissionEntry,
  type RoleCreate,
  type RoleUpdate,
} from "@/lib/api";
import { zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { StepUpSection } from "@/components/StepUpSection";
import { isStepUpRequired, stepUpBody } from "@/lib/stepup";
import { ResourceIdPicker } from "@/components/ownership/ResourceIdPicker";

// Mirror of docs/PERMISSIONS.md — keep these in sync.
const ACTIONS = ["read", "write", "delete", "admin", "*"] as const;
const RESOURCE_TYPES = [
  "*",
  "ip_space",
  "ip_block",
  "subnet",
  "ip_address",
  "address_set",
  "vlan",
  "dns_group",
  "dns_zone",
  "dns_record",
  "dns_blocklist",
  "dhcp_server",
  "dhcp_scope",
  "dhcp_pool",
  "dhcp_static",
  "dhcp_client_class",
  "audit_log",
  "user",
  "group",
  "role",
  "auth_provider",
  "custom_field",
  "manage_ipam_templates",
  "settings",
  "api_token",
] as const;

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}

function PermissionEditor({
  value,
  onChange,
}: {
  value: PermissionEntry[];
  onChange: (next: PermissionEntry[]) => void;
}) {
  function update(idx: number, patch: Partial<PermissionEntry>) {
    const next = value.slice();
    next[idx] = { ...next[idx], ...patch };
    onChange(next);
  }
  function remove(idx: number) {
    onChange(value.filter((_, i) => i !== idx));
  }
  function add() {
    onChange([...value, { action: "read", resource_type: "*" }]);
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs font-medium text-muted-foreground">
          Permissions
        </label>
        <button
          onClick={add}
          type="button"
          className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted"
        >
          <Plus className="h-3 w-3" /> Add row
        </button>
      </div>
      {value.length === 0 && (
        <p className="text-xs text-muted-foreground">
          No permissions. Add rows to grant access.
        </p>
      )}
      {value.map((p, idx) => (
        <div
          key={idx}
          className="grid grid-cols-[110px_1fr_1fr_32px] gap-2 items-center"
        >
          <select
            className={inputCls}
            value={p.action}
            onChange={(e) => update(idx, { action: e.target.value })}
          >
            {ACTIONS.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
          <select
            className={inputCls}
            value={p.resource_type}
            onChange={(e) => update(idx, { resource_type: e.target.value })}
          >
            {RESOURCE_TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <ResourceIdPicker
            className={inputCls}
            resourceType={p.resource_type}
            value={p.resource_id ?? null}
            onChange={(id) => update(idx, { resource_id: id })}
          />
          <button
            onClick={() => remove(idx)}
            type="button"
            className="flex h-full items-center justify-center rounded p-1 text-muted-foreground hover:text-destructive"
            title="Remove row"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

function RoleModal({
  role,
  onClose,
}: {
  role: AppRole | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(role?.name ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [permissions, setPermissions] = useState<PermissionEntry[]>(
    role?.permissions ?? [],
  );
  const [error, setError] = useState<string | null>(null);
  // #1412 — shown once the server says this change makes someone a
  // superadmin; the dialog cannot work that out itself.
  const [needsStepUp, setNeedsStepUp] = useState(false);
  const [stepPassword, setStepPassword] = useState("");
  const [stepTotp, setStepTotp] = useState("");

  const mutation = useMutation({
    mutationFn: () => {
      const payload: RoleCreate | RoleUpdate = {
        name,
        description,
        permissions,
      };
      return role
        ? rolesApi.update(role.id, {
            ...(payload as RoleUpdate),
            ...(needsStepUp ? stepUpBody(stepPassword, stepTotp) : {}),
          })
        : rolesApi.create(payload as RoleCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["roles"] });
      onClose();
    },
    onError: (err: unknown) => {
      if (isStepUpRequired(err)) {
        setNeedsStepUp(true);
        setError(null);
        return;
      }
      const msg =
        (err as { response?: { data?: { detail?: unknown } } })?.response?.data
          ?.detail ?? "Failed to save role";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
    },
  });

  const readOnly = role?.is_builtin ?? false;

  return (
    <Modal
      title={role ? `Edit role — ${role.name}` : "New Role"}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {readOnly && (
          <p className="rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">
            Built-in roles cannot be edited directly. Clone this role to make a
            customised copy.
          </p>
        )}
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            disabled={readOnly}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            disabled={readOnly}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <fieldset disabled={readOnly} className="disabled:opacity-60">
          <PermissionEditor value={permissions} onChange={setPermissions} />
        </fieldset>
        {needsStepUp && (
          <StepUpSection
            reason="This change makes members of the groups holding this role superadmins. Confirm it's you to save it."
            password={stepPassword}
            onPassword={setStepPassword}
            totp={stepTotp}
            onTotp={setStepTotp}
          />
        )}
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            {readOnly ? "Close" : "Cancel"}
          </button>
          {!readOnly && (
            <button
              onClick={() => {
                setError(null);
                mutation.mutate();
              }}
              disabled={
                !name ||
                mutation.isPending ||
                (needsStepUp && !stepPassword && !stepTotp)
              }
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {mutation.isPending ? "Saving…" : "Save"}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function CloneModal({ role, onClose }: { role: AppRole; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(`${role.name} (copy)`);
  const [error, setError] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () => rolesApi.clone(role.id, name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["roles"] });
      onClose();
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { detail?: unknown } } })?.response?.data
          ?.detail ?? "Clone failed";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
    },
  });

  return (
    <Modal title={`Clone role — ${role.name}`} onClose={onClose}>
      <div className="space-y-3">
        <Field label="New name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
        </Field>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
            disabled={!name || mutation.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mutation.isPending ? "Cloning…" : "Clone"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function DeleteModal({
  role,
  onClose,
}: {
  role: AppRole;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => rolesApi.delete(role.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["roles"] });
      onClose();
    },
  });
  return (
    <Modal title="Delete Role" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Delete role <strong className="text-foreground">{role.name}</strong>?
          Any groups referencing it will lose those permissions. This cannot be
          undone.
        </p>
        {/* A refused or failed delete says so; the dialog stays (#1344). */}
        {mutation.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(mutation.error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {mutation.isPending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function RolesPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [editRole, setEditRole] = useState<AppRole | null>(null);
  const [cloneRole, setCloneRole] = useState<AppRole | null>(null);
  const [deleteRole, setDeleteRole] = useState<AppRole | null>(null);

  const { data: roles, isLoading } = useQuery({
    queryKey: ["roles"],
    queryFn: rolesApi.list,
  });

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">Roles</h1>
            <p className="text-sm text-muted-foreground">
              Named permission sets. Assign roles to groups under{" "}
              <a href="/admin/groups" className="underline">
                Groups
              </a>
              .
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3.5 w-3.5" />
            New Role
          </button>
        </div>

        <div className="rounded-lg border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50 text-xs">
                <th className="px-4 py-3 text-left font-medium">Name</th>
                <th className="px-4 py-3 text-left font-medium">Description</th>
                <th className="px-4 py-3 text-left font-medium">Permissions</th>
                <th className="px-4 py-3 text-left font-medium">Built-in</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {isLoading && (
                <tr>
                  <td
                    colSpan={5}
                    className="px-4 py-6 text-center text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {roles?.map((role) => (
                <tr
                  key={role.id}
                  className="border-b last:border-0 hover:bg-muted/20"
                >
                  <td className="px-4 py-3 font-medium">{role.name}</td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {role.description || <span className="opacity-40">—</span>}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {role.permissions.length === 0
                      ? "none"
                      : `${role.permissions.length} entr${role.permissions.length === 1 ? "y" : "ies"}`}
                  </td>
                  <td className="px-4 py-3">
                    {role.is_builtin ? (
                      <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
                        built-in
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => setEditRole(role)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground"
                        title={role.is_builtin ? "View" : "Edit"}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setCloneRole(role)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground"
                        title="Clone"
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteRole(role)}
                        disabled={role.is_builtin}
                        className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-30"
                        title={
                          role.is_builtin
                            ? "Built-in roles cannot be deleted"
                            : "Delete"
                        }
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <RoleModal role={null} onClose={() => setShowCreate(false)} />
      )}
      {editRole && (
        <RoleModal role={editRole} onClose={() => setEditRole(null)} />
      )}
      {cloneRole && (
        <CloneModal role={cloneRole} onClose={() => setCloneRole(null)} />
      )}
      {deleteRole && (
        <DeleteModal role={deleteRole} onClose={() => setDeleteRole(null)} />
      )}
    </div>
  );
}

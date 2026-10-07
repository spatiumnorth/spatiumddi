import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import {
  groupsApi,
  rolesApi,
  usersApi,
  type AppRole,
  type AppUser,
  type InternalGroup,
  type InternalGroupCreate,
  type InternalGroupUpdate,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { StepUpSection } from "@/components/StepUpSection";
import { isStepUpRequired, stepUpBody } from "@/lib/stepup";
import { TimeBoundGrantsPanel } from "./TimeBoundGrantsPanel";

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

function MultiPicker<T extends { id: string }>({
  items,
  selected,
  onChange,
  labelFor,
  secondaryFor,
  placeholder = "No items",
}: {
  items: T[] | undefined;
  selected: string[];
  onChange: (ids: string[]) => void;
  labelFor: (item: T) => string;
  secondaryFor?: (item: T) => string | null;
  placeholder?: string;
}) {
  const [filter, setFilter] = useState("");
  const filtered = useMemo(() => {
    if (!items) return [];
    const f = filter.trim().toLowerCase();
    if (!f) return items;
    return items.filter((i) => labelFor(i).toLowerCase().includes(f));
  }, [items, filter, labelFor]);

  function toggle(id: string) {
    if (selected.includes(id)) {
      onChange(selected.filter((x) => x !== id));
    } else {
      onChange([...selected, id]);
    }
  }

  return (
    <div className="space-y-2">
      <input
        className={inputCls}
        placeholder="Filter…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <div className="max-h-52 overflow-y-auto rounded-md border">
        {filtered.length === 0 ? (
          <p className="p-3 text-xs text-muted-foreground">{placeholder}</p>
        ) : (
          filtered.map((item) => {
            const isOn = selected.includes(item.id);
            return (
              <label
                key={item.id}
                className={cn(
                  "flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm hover:bg-muted/40",
                  isOn && "bg-muted/60",
                )}
              >
                <input
                  type="checkbox"
                  checked={isOn}
                  onChange={() => toggle(item.id)}
                />
                <span className="flex-1">{labelFor(item)}</span>
                {secondaryFor && (
                  <span className="text-xs text-muted-foreground">
                    {secondaryFor(item)}
                  </span>
                )}
              </label>
            );
          })
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        {selected.length} selected
      </p>
    </div>
  );
}

function GroupModal({
  group,
  roles,
  users,
  onClose,
}: {
  group: InternalGroup | null;
  roles: AppRole[];
  users: AppUser[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [roleIds, setRoleIds] = useState<string[]>(group?.role_ids ?? []);
  const [userIds, setUserIds] = useState<string[]>(group?.user_ids ?? []);
  const [error, setError] = useState<string | null>(null);
  // #1412 — shown once the server says this change makes someone a
  // superadmin; the dialog cannot work that out itself.
  const [needsStepUp, setNeedsStepUp] = useState(false);
  const [stepPassword, setStepPassword] = useState("");
  const [stepTotp, setStepTotp] = useState("");

  const mutation = useMutation({
    mutationFn: () => {
      const payload: InternalGroupCreate | InternalGroupUpdate = {
        name,
        description,
        role_ids: roleIds,
        user_ids: userIds,
        ...(needsStepUp ? stepUpBody(stepPassword, stepTotp) : {}),
      };
      return group
        ? groupsApi.update(group.id, payload as InternalGroupUpdate)
        : groupsApi.create(payload as InternalGroupCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["groups"] });
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
          ?.detail ?? "Failed to save group";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
    },
  });

  return (
    <Modal
      title={group ? `Edit group — ${group.name}` : "New Group"}
      onClose={onClose}
      wide
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </Field>
          <Field label="Description">
            <input
              className={inputCls}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              Roles
            </p>
            <MultiPicker
              items={roles}
              selected={roleIds}
              onChange={setRoleIds}
              labelFor={(r) => r.name}
              secondaryFor={(r) => (r.is_builtin ? "built-in" : null)}
              placeholder="No roles defined"
            />
          </div>
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              Members
            </p>
            <MultiPicker
              items={users}
              selected={userIds}
              onChange={setUserIds}
              labelFor={(u) => u.username}
              secondaryFor={(u) => u.display_name}
              placeholder="No users"
            />
          </div>
        </div>

        {needsStepUp && (
          <StepUpSection
            reason="This change makes one or more members superadmins. Confirm it's you to save it."
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
            Cancel
          </button>
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
        </div>

        {/* Time-bound grants (#65) — only available once the group exists
            so a grant has something to attach to. */}
        {group && (
          <div className="border-t pt-4">
            <TimeBoundGrantsPanel groupId={group.id} groupName={group.name} />
          </div>
        )}
      </div>
    </Modal>
  );
}

function DeleteModal({
  group,
  onClose,
}: {
  group: InternalGroup;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => groupsApi.delete(group.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["groups"] });
      onClose();
    },
  });
  return (
    <Modal title="Delete Group" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Delete group <strong className="text-foreground">{group.name}</strong>
          ? Users will lose any permissions carried by this group's roles. This
          cannot be undone.
        </p>
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

export function GroupsPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [editGroup, setEditGroup] = useState<InternalGroup | null>(null);
  const [deleteGroup, setDeleteGroup] = useState<InternalGroup | null>(null);

  const { data: groups, isLoading } = useQuery({
    queryKey: ["groups"],
    queryFn: groupsApi.list,
  });
  const { data: roles } = useQuery({
    queryKey: ["roles"],
    queryFn: rolesApi.list,
  });
  const { data: users } = useQuery({
    queryKey: ["users"],
    queryFn: usersApi.list,
  });

  const roleById = useMemo(() => {
    const m = new Map<string, AppRole>();
    (roles ?? []).forEach((r) => m.set(r.id, r));
    return m;
  }, [roles]);

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">Groups</h1>
            <p className="text-sm text-muted-foreground">
              Collect users and assign roles. Manage the role definitions under{" "}
              <a href="/admin/roles" className="underline">
                Roles
              </a>
              .
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3.5 w-3.5" />
            New Group
          </button>
        </div>

        <div className="rounded-lg border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50 text-xs">
                <th className="px-4 py-3 text-left font-medium">Name</th>
                <th className="px-4 py-3 text-left font-medium">Description</th>
                <th className="px-4 py-3 text-left font-medium">Source</th>
                <th className="px-4 py-3 text-left font-medium">Roles</th>
                <th className="px-4 py-3 text-left font-medium">Members</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {isLoading && (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-6 text-center text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {groups?.map((group) => (
                <tr
                  key={group.id}
                  className="border-b last:border-0 hover:bg-muted/20"
                >
                  <td className="px-4 py-3 font-medium">{group.name}</td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {group.description || <span className="opacity-40">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
                      {group.auth_source}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {(group.role_ids ?? []).length === 0 ? (
                      <span className="text-muted-foreground">none</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {(group.role_ids ?? []).map((rid) => (
                          <span
                            key={rid}
                            className="rounded bg-primary/10 px-1.5 py-0.5 text-primary"
                          >
                            {roleById.get(rid)?.name ?? rid}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {(group.user_ids ?? []).length}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => setEditGroup(group)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground"
                        title="Edit"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteGroup(group)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive"
                        title="Delete"
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
        <GroupModal
          group={null}
          roles={roles ?? []}
          users={users ?? []}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editGroup && (
        <GroupModal
          group={editGroup}
          roles={roles ?? []}
          users={users ?? []}
          onClose={() => setEditGroup(null)}
        />
      )}
      {deleteGroup && (
        <DeleteModal group={deleteGroup} onClose={() => setDeleteGroup(null)} />
      )}
    </div>
  );
}

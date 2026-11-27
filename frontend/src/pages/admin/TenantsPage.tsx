import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Layers, Pencil, Plus, Trash2 } from "lucide-react";
import { Field } from "@/components/ui/field";
import { FormError } from "@/components/ui/form-error";
import { ListReadError } from "@/components/ui/list-read-error";
import { Modal } from "@/components/ui/modal";
import {
  formatApiError,
  formatDialogError,
  ipamApi,
  tenantsApi,
  type Tenant,
} from "@/lib/api";
import { countNoun } from "@/lib/count-noun";
import { apiErrorStatus } from "@/lib/refusal";
import { zebraBodyCls } from "@/lib/utils";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function TenantForm({
  tenant,
  onClose,
}: {
  tenant: Tenant | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(tenant?.name ?? "");
  const [description, setDescription] = useState(tenant?.description ?? "");
  const [error, setError] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () =>
      tenant
        ? tenantsApi.update(tenant.id, { name, description })
        : tenantsApi.create({ name, description }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tenants"] });
      onClose();
    },
    onError: (err: unknown) =>
      setError(formatDialogError(err, "Failed to save tenant")),
  });
  return (
    <Modal
      title={tenant ? `Edit tenant — ${tenant.name}` : "New Tenant"}
      onClose={onClose}
    >
      <div className="space-y-4">
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
        <FormError>{error}</FormError>
        <div className="flex justify-end gap-2">
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
            disabled={!name.trim() || mutation.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mutation.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// Put IP spaces into the tenant, or take them out. A space already in another
// tenant moves, and its blocks, subnets and addresses move with it.
function SpacesModal({
  tenant,
  onClose,
}: {
  tenant: Tenant;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const spaces = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: ipamApi.listSpaces,
  });
  const members = useQuery({
    queryKey: ["tenants", tenant.id, "spaces"],
    queryFn: () => tenantsApi.spaces(tenant.id),
  });
  const done = () => {
    qc.invalidateQueries({ queryKey: ["tenants"] });
    qc.invalidateQueries({ queryKey: ["ipam-spaces"] });
  };
  const assign = useMutation({
    mutationFn: (id: string) => tenantsApi.assignSpaces(tenant.id, [id]),
    onSuccess: done,
    onError: (e: unknown) => setError(formatDialogError(e, "Failed to assign")),
  });
  const unassign = useMutation({
    mutationFn: (id: string) => tenantsApi.unassignSpace(tenant.id, id),
    onSuccess: done,
    onError: (e: unknown) => setError(formatDialogError(e, "Failed to remove")),
  });
  const memberIds = new Set((members.data ?? []).map((m) => m.id));
  return (
    <Modal title={`IP spaces — ${tenant.name}`} onClose={onClose}>
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          A space belongs to at most one tenant. Its blocks, subnets and
          addresses belong with it.
        </p>
        {(spaces.error || members.error) && (
          <ListReadError
            error={spaces.error ?? members.error}
            what="IP spaces"
          />
        )}
        <ul className="max-h-72 divide-y overflow-auto rounded-md border text-sm">
          {(spaces.data ?? []).map((s) => {
            const mine = memberIds.has(s.id);
            const other = !mine && s.tenant_id;
            return (
              <li key={s.id} className="flex items-center gap-2 px-3 py-2">
                <Layers className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="flex-1 truncate">{s.name}</span>
                {other && (
                  <span className="text-xs text-muted-foreground">
                    in another tenant
                  </span>
                )}
                {mine ? (
                  <button
                    onClick={() => unassign.mutate(s.id)}
                    className="rounded-md border px-2 py-0.5 text-xs hover:bg-muted"
                  >
                    Remove
                  </button>
                ) : (
                  <button
                    onClick={() => assign.mutate(s.id)}
                    className="rounded-md border px-2 py-0.5 text-xs hover:bg-muted"
                  >
                    Add
                  </button>
                )}
              </li>
            );
          })}
        </ul>
        <FormError>{error}</FormError>
        <div className="flex justify-end">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function DeleteModal({
  tenant,
  onClose,
}: {
  tenant: Tenant;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => tenantsApi.remove(tenant.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tenants"] });
      onClose();
    },
    onError: (err: unknown) => {
      if (apiErrorStatus(err) === 404) {
        qc.invalidateQueries({ queryKey: ["tenants"] });
        onClose();
      }
    },
  });
  return (
    <Modal title="Delete Tenant" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Delete tenant{" "}
          <strong className="text-foreground">{tenant.name}</strong>? It must
          own no IP spaces and have no groups or tokens bound to it.
        </p>
        {mutation.isError && apiErrorStatus(mutation.error) !== 404 && (
          <FormError>{formatApiError(mutation.error)}</FormError>
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

export function TenantsPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<Tenant | null>(null);
  const [spacesFor, setSpacesFor] = useState<Tenant | null>(null);
  const [del, setDel] = useState<Tenant | null>(null);
  const { data, isLoading, error } = useQuery({
    queryKey: ["tenants"],
    queryFn: () => tenantsApi.list(),
  });
  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">Tenants</h1>
            <p className="text-sm text-muted-foreground">
              A tenant owns IP spaces. Users in a group bound to a tenant (set
              on the group) work only inside its spaces.
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3.5 w-3.5" />
            New Tenant
          </button>
        </div>
        {error ? (
          <ListReadError error={error} what="tenants" />
        ) : (
          <div className="rounded-lg border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50 text-xs">
                  <th className="px-4 py-3 text-left font-medium">Name</th>
                  <th className="px-4 py-3 text-left font-medium">
                    Description
                  </th>
                  <th className="px-4 py-3 text-left font-medium">Spaces</th>
                  <th className="px-4 py-3 text-left font-medium">Groups</th>
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
                {!isLoading && (data ?? []).length === 0 && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-6 text-center text-muted-foreground"
                    >
                      No tenants yet.
                    </td>
                  </tr>
                )}
                {(data ?? []).map((t) => (
                  <tr key={t.id} className="border-b last:border-0">
                    <td className="px-4 py-3 font-medium">{t.name}</td>
                    <td className="px-4 py-3 text-muted-foreground">
                      {t.description || <span className="opacity-40">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <button
                        className="underline"
                        onClick={() => setSpacesFor(t)}
                      >
                        {countNoun(t.space_count, "IP space")}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {countNoun(t.group_count, "group")}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setEdit(t)}
                          className="rounded p-1 text-muted-foreground hover:text-foreground"
                          title="Edit"
                          aria-label="Edit"
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setDel(t)}
                          className="rounded p-1 text-muted-foreground hover:text-destructive"
                          title="Delete"
                          aria-label="Delete"
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
        )}
      </div>
      {showCreate && (
        <TenantForm tenant={null} onClose={() => setShowCreate(false)} />
      )}
      {edit && <TenantForm tenant={edit} onClose={() => setEdit(null)} />}
      {spacesFor && (
        <SpacesModal tenant={spacesFor} onClose={() => setSpacesFor(null)} />
      )}
      {del && <DeleteModal tenant={del} onClose={() => setDel(null)} />}
    </div>
  );
}

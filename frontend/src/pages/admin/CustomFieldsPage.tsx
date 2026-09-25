import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { customFieldsApi, authApi, type CustomField } from "@/lib/api";
import { Plus, Pencil, Trash2, X, Check } from "lucide-react";
import { useModalDialog } from "@/components/ui/use-draggable-modal";

const RESOURCE_TYPES = ["ip_space", "ip_block", "subnet", "ip_address"];
const FIELD_TYPES = ["text", "number", "boolean", "select", "url", "email"];

const RESOURCE_LABELS: Record<string, string> = {
  ip_space: "IP Space",
  ip_block: "IP Block",
  subnet: "Subnet",
  ip_address: "IP Address",
};

const FIELD_TYPE_LABELS: Record<string, string> = {
  text: "Text",
  number: "Number",
  boolean: "Boolean",
  select: "Select (dropdown)",
  url: "URL",
  email: "Email",
};

type ModalMode = "create" | "edit";

interface FieldForm {
  resource_type: string;
  name: string;
  label: string;
  field_type: string;
  options: string;
  is_required: boolean;
  is_searchable: boolean;
  default_value: string;
  display_order: number;
  description: string;
}

const EMPTY_FORM: FieldForm = {
  resource_type: "subnet",
  name: "",
  label: "",
  field_type: "text",
  options: "",
  is_required: false,
  is_searchable: false,
  default_value: "",
  display_order: 0,
  description: "",
};

function FieldModal({
  mode,
  initial,
  onClose,
  onSave,
  error,
  saving,
}: {
  mode: ModalMode;
  initial: FieldForm;
  onClose: () => void;
  onSave: (form: FieldForm) => void;
  error?: string;
  saving: boolean;
}) {
  const [form, setForm] = useState<FieldForm>(initial);

  function set<K extends keyof FieldForm>(key: K, value: FieldForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  const { dialogProps, titleProps } = useModalDialog(onClose);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        {...dialogProps}
        className="relative z-10 w-full max-w-lg rounded-xl border bg-card shadow-2xl focus:outline-none"
      >
        <div className="flex items-center justify-between border-b px-5 py-4">
          <h2 {...titleProps} className="font-semibold">
            {mode === "create" ? "New Custom Field" : "Edit Custom Field"}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Resource Type
              </label>
              <select
                value={form.resource_type}
                onChange={(e) => set("resource_type", e.target.value)}
                disabled={mode === "edit"}
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60"
              >
                {RESOURCE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {RESOURCE_LABELS[t]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Field Type
              </label>
              <select
                value={form.field_type}
                onChange={(e) => set("field_type", e.target.value)}
                disabled={mode === "edit"}
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60"
              >
                {FIELD_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {FIELD_TYPE_LABELS[t]}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {mode === "create" && (
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Name{" "}
                <span className="text-muted-foreground/60">
                  (lowercase, underscores)
                </span>
              </label>
              <input
                value={form.name}
                onChange={(e) =>
                  set(
                    "name",
                    e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, "_"),
                  )
                }
                placeholder="e.g. location_code"
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm font-mono"
              />
            </div>
          )}

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Label
            </label>
            <input
              value={form.label}
              onChange={(e) => set("label", e.target.value)}
              placeholder="e.g. Location Code"
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Description
            </label>
            <input
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
              placeholder="Optional description"
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
            />
          </div>

          {form.field_type === "select" && (
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Options{" "}
                <span className="text-muted-foreground/60">
                  (comma-separated)
                </span>
              </label>
              <input
                value={form.options}
                onChange={(e) => set("options", e.target.value)}
                placeholder="Option A, Option B, Option C"
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Default Value
              </label>
              <input
                value={form.default_value}
                onChange={(e) => set("default_value", e.target.value)}
                placeholder="Optional"
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Display Order
              </label>
              <input
                type="number"
                value={form.display_order}
                onChange={(e) => set("display_order", Number(e.target.value))}
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              />
            </div>
          </div>

          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.is_required}
                onChange={(e) => set("is_required", e.target.checked)}
                className="h-4 w-4"
              />
              Required
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.is_searchable}
                onChange={(e) => set("is_searchable", e.target.checked)}
                className="h-4 w-4"
              />
              Searchable
            </label>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t px-5 py-4">
          <button
            onClick={onClose}
            className="rounded-md px-4 py-1.5 text-sm text-muted-foreground hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={saving || !form.name || !form.label}
            className="flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
          >
            <Check className="h-3.5 w-3.5" />
            {saving ? "Saving…" : mode === "create" ? "Create" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

function formToPayload(form: FieldForm): Omit<CustomField, "id"> {
  return {
    resource_type: form.resource_type,
    name: form.name,
    label: form.label,
    field_type: form.field_type,
    options:
      form.field_type === "select"
        ? form.options
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : null,
    is_required: form.is_required,
    is_searchable: form.is_searchable,
    default_value: form.default_value || null,
    display_order: form.display_order,
    description: form.description,
  };
}

function fieldToForm(field: CustomField): FieldForm {
  return {
    resource_type: field.resource_type,
    name: field.name,
    label: field.label,
    field_type: field.field_type,
    options: field.options ? field.options.join(", ") : "",
    is_required: field.is_required,
    is_searchable: field.is_searchable,
    default_value: field.default_value ?? "",
    display_order: field.display_order,
    description: field.description,
  };
}

// Its own component (#1156) so the dialog hook's Esc binding and focus trap
// mount and unmount with the dialog, not with the page.
function DeleteFieldDialog({
  field,
  pending,
  onConfirm,
  onClose,
}: {
  field: CustomField;
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { dialogProps, titleProps } = useModalDialog(onClose);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        {...dialogProps}
        className="relative z-10 w-full max-w-sm rounded-xl border bg-card p-6 shadow-2xl focus:outline-none"
      >
        <h2 {...titleProps} className="font-semibold">
          Delete Custom Field?
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Delete <span className="font-mono font-medium">{field.name}</span>{" "}
          from {RESOURCE_LABELS[field.resource_type]}? Existing data stored in
          this field will be lost.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md px-4 py-1.5 text-sm text-muted-foreground hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={pending}
            className="rounded-md bg-destructive px-4 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-40"
          >
            {pending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function CustomFieldsPage() {
  const qc = useQueryClient();
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const isSuperadmin = me?.is_superadmin ?? false;

  const [filterType, setFilterType] = useState<string>("all");
  const [modal, setModal] = useState<{
    mode: ModalMode;
    field?: CustomField;
  } | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<CustomField | null>(null);
  const [modalError, setModalError] = useState<string>("");

  const { data: fields = [], isLoading } = useQuery({
    queryKey: ["custom-fields"],
    queryFn: () => customFieldsApi.list(),
  });

  const createMutation = useMutation({
    mutationFn: customFieldsApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-fields"] });
      setModal(null);
      setModalError("");
    },
    onError: (e: unknown) => {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "Failed to create field";
      setModalError(msg);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: string;
      data: Parameters<typeof customFieldsApi.update>[1];
    }) => customFieldsApi.update(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-fields"] });
      setModal(null);
      setModalError("");
    },
    onError: (e: unknown) => {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "Failed to update field";
      setModalError(msg);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: customFieldsApi.delete,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-fields"] });
      setDeleteConfirm(null);
    },
  });

  function handleSave(form: FieldForm) {
    setModalError("");
    if (modal?.mode === "create") {
      createMutation.mutate(formToPayload(form));
    } else if (modal?.mode === "edit" && modal.field) {
      const {
        resource_type: _rt,
        name: _n,
        field_type: _ft,
        ...editable
      } = formToPayload(form);
      updateMutation.mutate({ id: modal.field.id, data: editable });
    }
  }

  const displayed =
    filterType === "all"
      ? fields
      : fields.filter((f) => f.resource_type === filterType);

  const grouped = RESOURCE_TYPES.reduce<Record<string, CustomField[]>>(
    (acc, rt) => {
      acc[rt] = displayed.filter((f) => f.resource_type === rt);
      return acc;
    },
    {},
  );

  if (isLoading) {
    return <div className="p-8 text-sm text-muted-foreground">Loading…</div>;
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold">Custom Fields</h1>
          <p className="text-sm text-muted-foreground">
            Define extra metadata fields for IPAM resources.
          </p>
        </div>
        {isSuperadmin && (
          <button
            onClick={() => {
              setModal({ mode: "create" });
              setModalError("");
            }}
            className="flex shrink-0 items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-4 w-4" />
            New Field
          </button>
        )}
      </div>

      {/* Filter */}
      <div className="flex gap-2">
        <button
          onClick={() => setFilterType("all")}
          className={`rounded-md px-3 py-1 text-sm ${filterType === "all" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent"}`}
        >
          All
        </button>
        {RESOURCE_TYPES.map((rt) => (
          <button
            key={rt}
            onClick={() => setFilterType(rt)}
            className={`rounded-md px-3 py-1 text-sm ${filterType === rt ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent"}`}
          >
            {RESOURCE_LABELS[rt]}
          </button>
        ))}
      </div>

      {fields.length === 0 && (
        <div className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
          No custom fields defined yet.
          {isSuperadmin && ' Click "New Field" to add one.'}
        </div>
      )}

      {RESOURCE_TYPES.map((rt) => {
        const items = grouped[rt];
        if (!items || items.length === 0) return null;
        return (
          <div key={rt} className="rounded-lg border bg-card">
            <div className="border-b px-5 py-3">
              <h2 className="text-sm font-semibold">{RESOURCE_LABELS[rt]}</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead>
                  <tr className="border-b text-xs text-muted-foreground">
                    <th className="px-5 py-2 text-left font-medium">Name</th>
                    <th className="px-5 py-2 text-left font-medium">Label</th>
                    <th className="px-5 py-2 text-left font-medium">Type</th>
                    <th className="px-5 py-2 text-left font-medium">Flags</th>
                    {isSuperadmin && (
                      <th className="px-5 py-2 text-right font-medium">
                        Actions
                      </th>
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {items.map((field) => (
                    <tr key={field.id} className="hover:bg-muted/30">
                      <td className="px-5 py-2 font-mono text-xs">
                        {field.name}
                      </td>
                      <td className="px-5 py-2">{field.label}</td>
                      <td className="px-5 py-2">
                        <span className="rounded bg-muted px-1.5 py-0.5 text-xs">
                          {FIELD_TYPE_LABELS[field.field_type] ??
                            field.field_type}
                        </span>
                      </td>
                      <td className="px-5 py-2">
                        <div className="flex gap-1">
                          {field.is_required && (
                            <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-600">
                              required
                            </span>
                          )}
                          {field.is_searchable && (
                            <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-600">
                              searchable
                            </span>
                          )}
                        </div>
                      </td>
                      {isSuperadmin && (
                        <td className="px-5 py-2 text-right">
                          <div className="flex justify-end gap-1">
                            <button
                              onClick={() => {
                                setModal({ mode: "edit", field });
                                setModalError("");
                              }}
                              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                              title="Edit"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </button>
                            <button
                              onClick={() => setDeleteConfirm(field)}
                              className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                              title="Delete"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}

      {/* Create/Edit Modal */}
      {modal && (
        <FieldModal
          mode={modal.mode}
          initial={modal.field ? fieldToForm(modal.field) : EMPTY_FORM}
          onClose={() => setModal(null)}
          onSave={handleSave}
          error={modalError}
          saving={createMutation.isPending || updateMutation.isPending}
        />
      )}

      {/* Delete confirm */}
      {deleteConfirm && (
        <DeleteFieldDialog
          field={deleteConfirm}
          pending={deleteMutation.isPending}
          onConfirm={() => deleteMutation.mutate(deleteConfirm.id)}
          onClose={() => setDeleteConfirm(null)}
        />
      )}
    </div>
  );
}

import { type FormEvent, useState } from "react";
import { Plus } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatApiError, ipamApi, type IPSpace } from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { SwatchPicker } from "@/components/ui/swatch-picker";

// Dropdown + "+ New" shortcut used inside the integration-endpoint modals
// (Proxmox / Kubernetes / Docker). Operators coming from a fresh install
// hit the endpoint-create modal before they've ever opened IPAM, so
// making them cancel out, build a space, and come back was a trap.
// The quick-create form is deliberately minimal — name + description +
// color. DNS/DHCP defaults and DDNS inheritance still live in the full
// IPAM page; the intent here is "get me over the required-field wall".

const selectCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

export function IPSpacePicker({
  value,
  onChange,
  required,
}: {
  value: string;
  onChange: (id: string) => void;
  required?: boolean;
}) {
  const { data: spaces = [] } = useQuery<IPSpace[]>({
    queryKey: ["spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });
  const [showCreate, setShowCreate] = useState(false);

  return (
    <>
      <div className="flex items-center gap-1">
        <select
          className={selectCls}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={required}
        >
          <option value="">— select —</option>
          {spaces.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="inline-flex shrink-0 items-center gap-1 rounded-md border px-2 py-1.5 text-xs hover:bg-muted"
          title="Create a new IP space"
        >
          <Plus className="h-3.5 w-3.5" />
          New
        </button>
      </div>
      {showCreate && (
        <QuickCreateSpaceModal
          onClose={() => setShowCreate(false)}
          onCreated={(space) => {
            onChange(space.id);
            setShowCreate(false);
          }}
        />
      )}
    </>
  );
}

function QuickCreateSpaceModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (space: IPSpace) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [color, setColor] = useState<string | null>(null);
  const [error, setError] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      ipamApi.createSpace({
        name,
        description,
        is_default: false,
        color,
      }),
    onSuccess: (space) => {
      qc.invalidateQueries({ queryKey: ["spaces"] });
      onCreated(space);
    },
    onError: (e) => {
      setError(formatApiError(e, "Failed to create space"));
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    // Stop the synthetic submit from bubbling up to the parent
    // modal's <form onSubmit> in React's component tree (portaling
    // the modal fixes DOM-level nesting but React's synthetic events
    // still bubble through the React tree). Without this, the parent
    // modal's save mutation fires when the operator clicks "Create"
    // on the quick-add space form.
    e.stopPropagation();
    if (!name.trim()) return;
    createMut.mutate();
  };

  return (
    <Modal title="New IP Space" onClose={onClose}>
      <form onSubmit={submit} className="space-y-3">
        <div className="space-y-1">
          <label className="block text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            className={selectCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Lab, Corporate"
            autoFocus
            required
          />
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium text-muted-foreground">
            Description
          </label>
          <input
            className={selectCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional"
          />
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium text-muted-foreground">
            Color
          </label>
          <SwatchPicker value={color} onChange={setColor} />
        </div>
        <p className="text-[11px] text-muted-foreground/70">
          DNS / DHCP defaults and DDNS settings can be added later from the IPAM
          page.
        </p>
        {error && (
          <p className="rounded border border-destructive/50 bg-destructive/10 px-2 py-1 text-xs text-destructive">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!name.trim() || createMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {createMut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

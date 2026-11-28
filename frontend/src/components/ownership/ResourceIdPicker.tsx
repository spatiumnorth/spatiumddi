import { useQuery } from "@tanstack/react-query";

import { useFieldControl } from "@/components/ui/field";
import { customersApi, ipamApi, providersApi, sitesApi } from "@/lib/api";

interface ResourceIdPickerProps {
  /** The permission's `resource_type`. Drives which list (if any) is
   *  offered as a dropdown. Unmapped types fall back to a raw text input. */
  resourceType: string;
  value: string | null;
  onChange: (id: string | null) => void;
  className?: string;
  disabled?: boolean;
}

/** An option rendered in the scoped-instance dropdown. */
interface PickerOption {
  id: string;
  label: string;
}

/** Per-resource_type list config. Each entry knows how to fetch a flat
 *  list of selectable instances and how to label each row. Only resource
 *  types that list flatly (no required parent id) are mapped — VLANs and
 *  DNS zones need a router/group id this picker doesn't have, so they fall
 *  through to the raw text input below.
 *
 *  The query keys are shared with the ownership pickers in `pickers.tsx`
 *  (`customers-picker` / `sites-picker` / `providers-picker`) so caches are
 *  reused rather than duplicated. */
const RESOURCE_TYPE_LIST_QUERY: Record<
  string,
  { queryKey: unknown[]; queryFn: () => Promise<PickerOption[]> }
> = {
  ip_space: {
    queryKey: ["resource-id-picker", "ip_space"],
    queryFn: () =>
      ipamApi
        .listSpaces()
        .then((rows) => rows.map((s) => ({ id: s.id, label: s.name }))),
  },
  ip_block: {
    queryKey: ["resource-id-picker", "ip_block"],
    queryFn: () =>
      ipamApi.listBlocks().then((rows) =>
        rows.map((b) => ({
          id: b.id,
          label: b.name ? `${b.name} (${b.network})` : b.network,
        })),
      ),
  },
  subnet: {
    queryKey: ["resource-id-picker", "subnet"],
    queryFn: () =>
      ipamApi.listSubnets().then((rows) =>
        rows.map((s) => ({
          id: s.id,
          label: s.name ? `${s.name} (${s.network})` : s.network,
        })),
      ),
  },
  customer: {
    queryKey: ["customers-picker"],
    queryFn: () =>
      customersApi
        .list({ limit: 500 })
        .then((r) => r.items.map((c) => ({ id: c.id, label: c.name }))),
  },
  site: {
    queryKey: ["sites-picker"],
    queryFn: () =>
      sitesApi.list({ limit: 500 }).then((r) =>
        r.items.map((s) => ({
          id: s.id,
          label: s.code ? `${s.name} (${s.code})` : s.name,
        })),
      ),
  },
  provider: {
    queryKey: ["providers-picker"],
    queryFn: () =>
      providersApi
        .list({ limit: 500 })
        .then((r) => r.items.map((p) => ({ id: p.id, label: p.name }))),
  },
};

/** Resource-id input for a permission row. When `resourceType` maps to a
 *  flat-listable resource (IP space / block / subnet, customer / site /
 *  provider), renders a `<select>` of named instances so operators don't
 *  paste raw UUIDs. For every other type (`*`, `settings`, `manage_*`,
 *  `audit_log`, …) it falls back to the original free-text input so no
 *  capability is lost. Empty selection / blank text ⇒ `null` (whole type). */
export function ResourceIdPicker({
  resourceType,
  value,
  onChange,
  className,
  disabled,
}: ResourceIdPickerProps) {
  const fieldControl = useFieldControl();
  const config = RESOURCE_TYPE_LIST_QUERY[resourceType];

  const { data } = useQuery({
    queryKey: config?.queryKey ?? ["resource-id-picker", "noop"],
    // ``config`` may be undefined for unmapped resource types; the query is
    // gated off via ``enabled`` below so this never actually runs, but supply
    // a safe no-op fn instead of a non-null assertion that would crash if the
    // ``enabled`` gate ever changed.
    queryFn: config ? config.queryFn : async () => [] as PickerOption[],
    staleTime: 60_000,
    enabled: !!config && !disabled,
  });

  if (!config) {
    return (
      <input
        {...fieldControl}
        className={className}
        placeholder="resource_id (optional)"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value || null)}
        disabled={disabled}
      />
    );
  }

  const options = data ?? [];
  // If the current value isn't in the loaded list (stale id, or list not
  // yet fetched) keep it selectable so we don't silently drop it.
  const hasValue = value != null && value !== "";
  const valueMissing = hasValue && !options.some((o) => o.id === value);

  return (
    <select
      {...fieldControl}
      className={className}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || null)}
      disabled={disabled}
    >
      <option value="">— Whole resource type —</option>
      {valueMissing && <option value={value!}>{value}</option>}
      {options.map((o) => (
        <option key={o.id} value={o.id}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

import { useQuery } from "@tanstack/react-query";

import { usePermissions } from "@/hooks/usePermissions";
import { asnsApi } from "@/lib/api";

interface AsnPickerProps {
  value: string | null;
  onChange: (asnId: string | null) => void;
  className?: string;
  disabled?: boolean;
}

/** Single-select dropdown bound to the ASN list. NULL = "no AS recorded". */
export function AsnPicker({
  value,
  onChange,
  className,
  disabled,
}: AsnPickerProps) {
  // The list route needs read on "manage_asns"; without it the list is never
  // asked (#3451) and the picker says why instead of offering only "None".
  const canRead = usePermissions().can("read", "manage_asns");
  const { data } = useQuery({
    queryKey: ["asns-picker"],
    queryFn: () => asnsApi.list({ limit: 500 }),
    staleTime: 60_000,
    enabled: canRead,
  });
  const asns = data?.items ?? [];

  if (!canRead) {
    // Disabled, so the form still sends the unchanged id (never a clear).
    return (
      <select
        className={className}
        value={value ? "linked" : ""}
        disabled
        title="Your role cannot read ASNs, so this cannot be changed here."
      >
        <option value="">— None —</option>
        {value && (
          <option value="linked">Linked (not visible to your role)</option>
        )}
      </select>
    );
  }

  return (
    <select
      className={className}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || null)}
      disabled={disabled}
    >
      <option value="">— None —</option>
      {asns.map((a) => (
        <option key={a.id} value={a.id}>
          AS{a.number}
          {a.name ? ` — ${a.name}` : ""}
          {a.kind === "private" ? " (private)" : ""}
        </option>
      ))}
    </select>
  );
}

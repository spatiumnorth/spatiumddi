import { useQuery } from "@tanstack/react-query";

import { usePermissions } from "@/hooks/usePermissions";
import { vrfsApi, type VRF } from "@/lib/api";

interface VrfPickerProps {
  value: string | null;
  onChange: (vrfId: string | null) => void;
  className?: string;
  disabled?: boolean;
}

/** Single-select dropdown bound to the VRF list. NULL = "no VRF". */
export function VrfPicker({
  value,
  onChange,
  className,
  disabled,
}: VrfPickerProps) {
  // The list route needs read on "vrf"; without it the list is never
  // asked (#3451) and the picker says why instead of offering only "None".
  const canRead = usePermissions().can("read", "vrf");
  const { data } = useQuery({
    queryKey: ["vrfs-picker"],
    queryFn: () => vrfsApi.list(),
    staleTime: 60_000,
    enabled: canRead,
  });
  const vrfs = data ?? [];

  if (!canRead) {
    // Disabled, so the form still sends the unchanged id (never a clear).
    return (
      <select
        className={className}
        value={value ? "linked" : ""}
        disabled
        title="Your role cannot read VRFs, so this cannot be changed here."
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
      {vrfs.map((v: VRF) => (
        <option key={v.id} value={v.id}>
          {v.name}
          {v.route_distinguisher ? ` — RD ${v.route_distinguisher}` : ""}
        </option>
      ))}
    </select>
  );
}

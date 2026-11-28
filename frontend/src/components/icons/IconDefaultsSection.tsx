import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { IconField } from "@/components/icons/IconField";
import { EntityIcon } from "@/components/icons/EntityIcon";
import { Field } from "@/components/ui/field";
import { FormError } from "@/components/ui/form-error";
import { ListReadError } from "@/components/ui/list-read-error";
import { usePermissions } from "@/hooks/usePermissions";
import {
  formatApiError,
  iconsApi,
  type IconDefault,
  type IconDefaultKind,
} from "@/lib/api";
import { countNoun } from "@/lib/count-noun";
import { iconLabel } from "@/lib/icons/catalog";

const KINDS: { kind: IconDefaultKind; title: string; hint: string }[] = [
  {
    kind: "device_class",
    title: "Device class",
    hint: "The device class a fingerprint lookup reports (matched case-insensitively).",
  },
  {
    kind: "ip_role",
    title: "IP role",
    hint: "The role set on an IP address, when no device class matches.",
  },
];

/** Settings -> Icons (#5022): the mapping from a device class or IP role to the icon a row shows when it has none of its own.
 *  The shipped mapping lives in the server; a row here exists only where an
 *  operator changed or added one, and Reset returns to the shipped icon. */
export function IconDefaultsSection() {
  const qc = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("write", "icon");
  const canDelete = can("delete", "icon");
  const [error, setError] = useState("");
  const [newKind, setNewKind] = useState<IconDefaultKind>("device_class");
  const [newMatch, setNewMatch] = useState("");
  const [newIcon, setNewIcon] = useState<string | null>(null);

  const {
    data: items = [],
    error: loadError,
    isLoading,
  } = useQuery({
    queryKey: ["icon-defaults"],
    queryFn: iconsApi.listDefaults,
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["icon-defaults"] });
    // Rows resolve their icon from these mappings.
    qc.invalidateQueries({ queryKey: ["addresses"] });
    qc.invalidateQueries({ queryKey: ["dns-records"] });
  };
  const save = useMutation({
    mutationFn: iconsApi.setDefault,
    onSuccess: () => {
      setError("");
      refresh();
    },
    onError: (e) => setError(formatApiError(e, "Could not save the icon")),
  });
  const reset = useMutation({
    mutationFn: (d: IconDefault) =>
      iconsApi.resetDefault(d.kind, d.match_value),
    onSuccess: () => {
      setError("");
      refresh();
    },
    onError: (e) => setError(formatApiError(e, "Could not reset the icon")),
  });

  if (loadError)
    return <ListReadError error={loadError} what="icon mappings" />;
  if (isLoading)
    return <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-6">
      <p className="text-xs text-muted-foreground">
        An IP address or DNS record with no icon of its own shows the icon
        mapped here: first by device class, then by IP role. A DNS record uses
        the icon of the IP address it points at.
      </p>
      <FormError>{error}</FormError>
      {KINDS.map(({ kind, title, hint }) => {
        const rows = items.filter((d) => d.kind === kind);
        return (
          <section key={kind} aria-label={title} className="space-y-2">
            <div>
              <h3 className="text-sm font-semibold">{title}</h3>
              <p className="text-[11px] text-muted-foreground">
                {hint} {countNoun(rows.length, "mapping")}.
              </p>
            </div>
            <ul className="divide-y rounded-md border">
              {rows.map((d) => (
                <li
                  key={`${d.kind}:${d.match_value}`}
                  className="flex items-center gap-3 px-3 py-2 text-sm"
                >
                  <EntityIcon icon={d.icon} decorative size={20} />
                  <span className="flex-1 font-mono text-xs">
                    {d.match_value}
                  </span>
                  <span className="w-28 text-xs text-muted-foreground">
                    {d.overridden
                      ? "changed"
                      : d.default_icon === null
                        ? "added"
                        : "shipped"}
                  </span>
                  <div className="w-56">
                    <IconField
                      value={d.icon}
                      disabled={!canWrite}
                      onChange={(v) => {
                        // "Automatic" in the picker = the shipped mapping.
                        if (v === null) {
                          if (canDelete) reset.mutate(d);
                          return;
                        }
                        save.mutate({
                          kind: d.kind,
                          match_value: d.match_value,
                          icon: v,
                        });
                      }}
                    />
                  </div>
                  {(d.overridden || d.default_icon === null) && (
                    <button
                      type="button"
                      disabled={!canDelete || reset.isPending}
                      onClick={() => reset.mutate(d)}
                      title={
                        d.default_icon === null
                          ? `Remove the mapping for ${d.match_value}`
                          : `Return ${d.match_value} to ${iconLabel(d.default_icon)}`
                      }
                      className="rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
                    >
                      {d.default_icon === null ? "Remove" : "Reset"}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </section>
        );
      })}

      {canWrite && (
        <section aria-label="Add a mapping" className="space-y-2">
          <h3 className="text-sm font-semibold">Add a mapping</h3>
          <form
            className="grid grid-cols-1 gap-3 sm:grid-cols-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!newMatch.trim() || !newIcon) return;
              save.mutate(
                { kind: newKind, match_value: newMatch.trim(), icon: newIcon },
                {
                  onSuccess: () => {
                    setNewMatch("");
                    setNewIcon(null);
                  },
                },
              );
            }}
          >
            <Field label="Applies to">
              <select
                value={newKind}
                onChange={(e) => setNewKind(e.target.value as IconDefaultKind)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              >
                {KINDS.map((k) => (
                  <option key={k.kind} value={k.kind}>
                    {k.title}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Value to match">
              <input
                value={newMatch}
                onChange={(e) => setNewMatch(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
                placeholder="e.g. Printer"
              />
            </Field>
            <Field label="Icon">
              <IconField value={newIcon} onChange={setNewIcon} />
            </Field>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={!newMatch.trim() || !newIcon || save.isPending}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
              >
                Add mapping
              </button>
            </div>
          </form>
        </section>
      )}
    </div>
  );
}

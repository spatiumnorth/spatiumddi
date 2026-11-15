import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Sparkles } from "lucide-react";
import { Modal } from "@/components/ui/modal";
import {
  dnsApi,
  formatApiError,
  type DNSZone,
  type ZoneTemplate,
} from "@/lib/api";
import { FormError } from "@/components/ui/form-error";

/**
 * Zone-template starter wizard.
 *
 * Operator picks a template from the static catalog (e.g. "Email zone",
 * "Active Directory zone"), fills in the parameter form, and the backend
 * stamps a fresh zone with the materialised records in one transaction.
 * Replaces the manual "create zone, then add five records by hand" loop
 * for common starter shapes.
 */
export function ZoneTemplateModal({
  groupId,
  onClose,
  onCreated,
}: {
  groupId: string;
  onClose: () => void;
  onCreated: (zone: DNSZone) => void;
}) {
  const qc = useQueryClient();

  const { data: catalog, isLoading } = useQuery({
    queryKey: ["dns-zone-templates"],
    queryFn: () => dnsApi.listZoneTemplates(),
    staleTime: 60 * 60 * 1000,
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [zoneName, setZoneName] = useState("");
  const [params, setParams] = useState<Record<string, string>>({});

  const selected: ZoneTemplate | null = useMemo(() => {
    if (!catalog || !selectedId) return null;
    return catalog.templates.find((t) => t.id === selectedId) ?? null;
  }, [catalog, selectedId]);

  function pickTemplate(t: ZoneTemplate) {
    setSelectedId(t.id);
    // Seed defaults from the template parameter manifest.
    const seed: Record<string, string> = {};
    for (const p of t.parameters) {
      if (p.default) seed[p.key] = p.default;
    }
    setParams(seed);
  }

  const createMut = useMutation({
    mutationFn: () => {
      if (!selected) throw new Error("Pick a template first");
      if (!zoneName.trim()) throw new Error("Zone name is required");
      return dnsApi.createZoneFromTemplate(groupId, {
        template_id: selected.id,
        zone_name: zoneName.trim(),
        params,
      });
    },
    onSuccess: (zone) => {
      qc.invalidateQueries({ queryKey: ["dns-zones", groupId] });
      onCreated(zone);
    },
  });

  const grouped = useMemo(() => {
    if (!catalog) return new Map<string, ZoneTemplate[]>();
    const m = new Map<string, ZoneTemplate[]>();
    for (const t of catalog.templates) {
      const arr = m.get(t.category) ?? [];
      arr.push(t);
      m.set(t.category, arr);
    }
    return m;
  }, [catalog]);

  return (
    <Modal title="Create zone from template" onClose={onClose} wide>
      <div className="grid grid-cols-[260px_1fr] gap-3 text-sm">
        <div className="max-h-[60vh] overflow-y-auto rounded border bg-muted/20 p-1">
          {isLoading && (
            <p className="px-2 py-2 text-xs text-muted-foreground">
              <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />
              Loading…
            </p>
          )}
          {[...grouped.entries()].map(([cat, list]) => (
            <div key={cat} className="mb-2">
              <p className="px-2 pt-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                {cat}
              </p>
              {list.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => pickTemplate(t)}
                  className={`block w-full rounded px-2 py-1.5 text-left text-xs hover:bg-accent ${
                    selectedId === t.id ? "bg-accent" : ""
                  }`}
                >
                  <span className="font-medium">{t.name}</span>
                  <span className="ml-1.5 text-[10px] text-muted-foreground">
                    {t.record_count} record{t.record_count !== 1 ? "s" : ""}
                  </span>
                </button>
              ))}
            </div>
          ))}
        </div>

        <div className="space-y-3">
          {!selected && (
            <p className="flex items-center gap-2 px-1 py-3 text-xs text-muted-foreground">
              <Sparkles className="h-3 w-3" /> Pick a template to see its
              parameter form.
            </p>
          )}
          {selected && (
            <>
              <p className="rounded bg-muted/30 px-2 py-1.5 text-xs text-muted-foreground">
                {selected.description}
              </p>

              <div>
                <label className="mb-0.5 block text-xs font-medium">
                  Zone name
                </label>
                <input
                  type="text"
                  value={zoneName}
                  onChange={(e) => setZoneName(e.target.value)}
                  placeholder="example.com"
                  className="w-full rounded border bg-background px-2 py-1 text-xs"
                />
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  The zone the new records will live in. Trailing dot is
                  optional — the API normalises either form.
                </p>
              </div>

              {selected.parameters.length === 0 && (
                <p className="rounded border bg-muted/20 px-2 py-2 text-[11px] text-muted-foreground">
                  This template has no parameters; submitting will create the
                  zone with no preset records.
                </p>
              )}

              {selected.parameters.map((p) => (
                <div key={p.key}>
                  <label className="mb-0.5 block text-xs font-medium">
                    {p.label}
                    {p.required && (
                      <span className="ml-1 text-destructive">*</span>
                    )}
                  </label>
                  <input
                    type="text"
                    value={params[p.key] ?? ""}
                    onChange={(e) =>
                      setParams((prev) => ({
                        ...prev,
                        [p.key]: e.target.value,
                      }))
                    }
                    placeholder={p.placeholder ?? ""}
                    className="w-full rounded border bg-background px-2 py-1 text-xs"
                  />
                  {p.hint && (
                    <p className="mt-0.5 text-[11px] text-muted-foreground">
                      {p.hint}
                    </p>
                  )}
                </div>
              ))}

              {createMut.isError && (
                <FormError className="text-xs text-destructive">
                  {formatApiError(createMut.error, "Could not create zone")}
                </FormError>
              )}

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => createMut.mutate()}
                  disabled={createMut.isPending || !zoneName.trim()}
                  className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                >
                  {createMut.isPending && (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  )}
                  Create zone
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </Modal>
  );
}

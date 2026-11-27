import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Modal } from "@/components/ui/modal";
import {
  dnsApi,
  formatApiError,
  type ApplyTemplateItem,
  type ApplyTemplatePreview,
  type ApplyTemplateStatus,
  type DNSZone,
  type ZoneTemplate,
} from "@/lib/api";
import { FormError } from "@/components/ui/form-error";
import { Field } from "@/components/ui/field";

const STATUS_LABEL: Record<ApplyTemplateStatus, string> = {
  add: "Add",
  present: "Already present",
  conflict: "Conflict",
  unsupported: "Unsupported",
};

const STATUS_CLASS: Record<ApplyTemplateStatus, string> = {
  add: "text-emerald-600 dark:text-emerald-400",
  present: "text-muted-foreground",
  conflict: "text-destructive",
  unsupported: "text-amber-600 dark:text-amber-400",
};

function recordText(i: ApplyTemplateItem): string {
  const fields = [i.priority, i.weight, i.port].filter((n) => n != null);
  return [...fields, i.value].join(" ");
}

/**
 * Apply a record template to an existing zone (#2183): pick a template, fill
 * its parameters, preview what each record would do, then apply. The preview
 * writes nothing; a conflicting record is never overwritten, it is shown and
 * left for the operator.
 */
export function ApplyTemplateModal({
  groupId,
  zone,
  onClose,
}: {
  groupId: string;
  zone: DNSZone;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const { data: catalog, isLoading } = useQuery({
    queryKey: ["dns-zone-templates"],
    queryFn: () => dnsApi.listZoneTemplates(),
    staleTime: 60 * 60 * 1000,
  });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [params, setParams] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<ApplyTemplatePreview | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const templates = useMemo(
    () => (catalog?.templates ?? []).filter((t) => t.record_count > 0),
    [catalog],
  );
  const selected: ZoneTemplate | null =
    templates.find((t) => t.id === selectedId) ?? null;

  function pick(t: ZoneTemplate) {
    setSelectedId(t.id);
    const seed: Record<string, string> = {};
    for (const p of t.parameters) if (p.default) seed[p.key] = p.default;
    setParams(seed);
    setPreview(null);
    setDone(null);
  }

  const previewMut = useMutation({
    mutationFn: () =>
      dnsApi.previewApplyTemplate(groupId, zone.id, {
        template_id: selected!.id,
        params,
      }),
    onSuccess: (p) => {
      setPreview(p);
      setDone(null);
    },
  });

  const applyMut = useMutation({
    mutationFn: (skip: boolean) =>
      dnsApi.applyTemplate(groupId, zone.id, {
        template_id: selected!.id,
        params,
        skip_conflicts: skip,
      }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      qc.invalidateQueries({ queryKey: ["dns-zones", groupId] });
      setPreview(null);
      setDone(
        `Added ${r.created} record${r.created === 1 ? "" : "s"}` +
          (r.present ? `; ${r.present} already present` : "") +
          (r.skipped.length > r.present
            ? `; ${r.skipped.length - r.present} left alone`
            : "") +
          ".",
      );
    },
  });

  const blocked = preview ? preview.conflict + preview.unsupported : 0;

  return (
    <Modal title={`Apply template to ${zone.name}`} onClose={onClose} wide>
      <div className="grid grid-cols-[240px_1fr] gap-3 text-sm">
        <div className="max-h-[60vh] overflow-y-auto rounded border bg-muted/20 p-1">
          {isLoading && (
            <p className="px-2 py-2 text-xs text-muted-foreground">
              <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />
              Loading…
            </p>
          )}
          {templates.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => pick(t)}
              className={`block w-full rounded px-2 py-1.5 text-left text-xs hover:bg-accent ${
                selectedId === t.id ? "bg-accent" : ""
              }`}
            >
              <span className="font-medium">{t.name}</span>
              <span className="ml-1.5 text-[10px] text-muted-foreground">
                {t.category}
              </span>
            </button>
          ))}
        </div>

        <div className="space-y-3">
          {!selected && (
            <p className="px-1 py-3 text-xs text-muted-foreground">
              Pick a template. Its records are previewed against this zone
              before anything is written.
            </p>
          )}
          {selected && (
            <>
              <p className="rounded bg-muted/30 px-2 py-1.5 text-xs text-muted-foreground">
                {selected.description}
                {selected.source && (
                  <>
                    {" "}
                    <a
                      href={selected.source}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="underline"
                    >
                      Source
                    </a>
                  </>
                )}
              </p>
              {selected.parameters.map((p) => (
                <Field
                  key={p.key}
                  label={p.required ? `${p.label} *` : p.label}
                  hint={p.hint}
                >
                  <input
                    type="text"
                    value={params[p.key] ?? ""}
                    onChange={(e) => {
                      setParams((prev) => ({
                        ...prev,
                        [p.key]: e.target.value,
                      }));
                      setPreview(null);
                    }}
                    placeholder={p.placeholder ?? ""}
                    className="w-full rounded border bg-background px-2 py-1 text-xs"
                  />
                </Field>
              ))}

              {preview && (
                <div className="rounded border">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/40 text-left">
                      <tr>
                        <th className="px-2 py-1">Name</th>
                        <th className="px-2 py-1">Type</th>
                        <th className="px-2 py-1">Value</th>
                        <th className="px-2 py-1">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.items.map((i, n) => (
                        <tr key={n} className="border-t align-top">
                          <td className="px-2 py-1 font-mono">{i.name}</td>
                          <td className="px-2 py-1">{i.record_type}</td>
                          <td className="break-all px-2 py-1 font-mono">
                            {recordText(i)}
                          </td>
                          <td className="px-2 py-1">
                            <span className={STATUS_CLASS[i.status]}>
                              {STATUS_LABEL[i.status]}
                            </span>
                            {i.reason && i.status !== "present" && (
                              <p className="text-[11px] text-muted-foreground">
                                {i.reason}
                              </p>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {done && (
                <p className="rounded bg-emerald-500/10 px-2 py-1.5 text-xs">
                  {done}
                </p>
              )}
              {(previewMut.isError || applyMut.isError) && (
                <FormError className="text-xs text-destructive">
                  {formatApiError(
                    previewMut.error ?? applyMut.error,
                    "Could not apply the template",
                  )}
                </FormError>
              )}

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={() => previewMut.mutate()}
                  disabled={previewMut.isPending}
                  className="inline-flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs hover:bg-muted/50 disabled:opacity-50"
                >
                  {previewMut.isPending && (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  )}
                  Preview
                </button>
                {preview && (
                  <button
                    type="button"
                    onClick={() => applyMut.mutate(blocked > 0)}
                    disabled={applyMut.isPending || preview.add === 0}
                    className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {applyMut.isPending && (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    )}
                    {blocked > 0
                      ? `Apply ${preview.add}, leave ${blocked} alone`
                      : `Apply ${preview.add} record${preview.add === 1 ? "" : "s"}`}
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </Modal>
  );
}

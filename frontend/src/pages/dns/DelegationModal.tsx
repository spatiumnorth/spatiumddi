import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, ArrowRight, CheckCircle2, Loader2 } from "lucide-react";
import { Modal } from "@/components/ui/modal";
import { dnsApi, formatApiError, type DelegationRecord } from "@/lib/api";
import { FormError } from "@/components/ui/form-error";

/**
 * Zone-delegation wizard.
 *
 * Computes the NS + glue records the parent zone needs so recursive
 * resolvers can find the child zone, lists exactly what would be created,
 * and lets the operator commit. Idempotent — already-present records are
 * shown in the "Skipped" section and not re-created on apply.
 */
export function DelegationModal({
  groupId,
  zoneId,
  zoneName,
  onClose,
}: {
  groupId: string;
  zoneId: string;
  zoneName: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dns-delegation-preview", groupId, zoneId],
    queryFn: () => dnsApi.getDelegationPreview(groupId, zoneId),
  });

  const applyMut = useMutation({
    mutationFn: () => dnsApi.applyDelegation(groupId, zoneId),
    onSuccess: () => {
      // The parent zone's record list changed — invalidate any cached view.
      qc.invalidateQueries({ queryKey: ["dns-records"] });
      qc.invalidateQueries({
        queryKey: ["dns-delegation-preview", groupId, zoneId],
      });
      // Refresh so operator sees the apply succeed in-modal before closing.
      void refetch();
    },
  });

  const childDisplay = zoneName.replace(/\.$/, "");

  return (
    <Modal title={`Delegate ${childDisplay}`} onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        {isLoading && (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" /> Computing preview…
          </p>
        )}
        {error && (
          <FormError className="text-xs text-destructive">
            {formatApiError(error, "Could not load delegation preview")}
          </FormError>
        )}

        {data && data.has_parent === false && (
          <p className="text-xs text-muted-foreground">
            No parent zone for <code className="font-mono">{childDisplay}</code>{" "}
            exists in this server group, so there is nothing to delegate. Create
            the parent zone first (e.g.{" "}
            <code className="font-mono">
              {childDisplay.split(".").slice(1).join(".") || "example.com"}
            </code>
            ) and add this zone again afterwards.
          </p>
        )}

        {data && data.has_parent === true && (
          <>
            <div className="rounded border bg-muted/30 p-3 text-xs">
              <div className="flex items-center gap-2 font-mono">
                <span>{childDisplay}</span>
                <ArrowRight className="h-3 w-3 text-muted-foreground" />
                <span>{data.parent_zone_name.replace(/\.$/, "")}</span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                These records will be created in the parent zone so recursive
                resolvers can find{" "}
                <code className="font-mono">{childDisplay}</code> through normal
                NS-chasing. The records mirror this zone's apex NS records.
              </p>
            </div>

            {data.warnings.length > 0 && (
              <div className="rounded border border-amber-300 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-200">
                <div className="mb-1 flex items-center gap-1.5 font-medium">
                  <AlertCircle className="h-3 w-3" /> Warnings
                </div>
                <ul className="ml-5 list-disc space-y-0.5">
                  {data.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            <RecordSection
              title="NS records to create in parent"
              records={data.ns_records_to_create}
              parentZone={data.parent_zone_name}
              emptyHint="None — every required NS record already exists in the parent."
            />

            <RecordSection
              title="Glue records to create in parent"
              records={data.glue_records_to_create}
              parentZone={data.parent_zone_name}
              hint="Glue is needed when an NS hostname falls inside the child zone — without it resolvers can't bootstrap to find the nameservers."
              emptyHint={
                data.ns_records_to_create.some((r) => r.record_type === "NS")
                  ? "No glue needed — none of the NS hostnames are in-bailiwick."
                  : "—"
              }
            />

            {(data.existing_ns_records.length > 0 ||
              data.existing_glue_records.length > 0) && (
              <RecordSection
                title="Already in parent (skipped)"
                records={[
                  ...data.existing_ns_records,
                  ...data.existing_glue_records,
                ]}
                parentZone={data.parent_zone_name}
                muted
              />
            )}

            {applyMut.isError && (
              <FormError className="text-xs text-destructive">
                {formatApiError(applyMut.error, "Apply failed")}
              </FormError>
            )}
            {applyMut.isSuccess && (
              <p className="flex items-center gap-1.5 text-xs text-emerald-600">
                <CheckCircle2 className="h-3 w-3" /> Delegation records created
                in {data.parent_zone_name.replace(/\.$/, "")}.
              </p>
            )}
          </>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
          >
            Close
          </button>
          {data?.has_parent === true && (
            <button
              type="button"
              onClick={() => applyMut.mutate()}
              disabled={
                applyMut.isPending ||
                data.child_apex_ns_count === 0 ||
                (data.ns_records_to_create.length === 0 &&
                  data.glue_records_to_create.length === 0)
              }
              className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {applyMut.isPending && (
                <Loader2 className="h-3 w-3 animate-spin" />
              )}
              {data.ns_records_to_create.length === 0 &&
              data.glue_records_to_create.length === 0
                ? "Nothing to delegate"
                : "Apply delegation"}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function RecordSection({
  title,
  records,
  parentZone,
  hint,
  emptyHint,
  muted,
}: {
  title: string;
  records: DelegationRecord[];
  parentZone: string;
  hint?: string;
  emptyHint?: string;
  muted?: boolean;
}) {
  return (
    <div
      className={`rounded border ${muted ? "bg-muted/30" : "bg-card"}`.trim()}
    >
      <div className="border-b px-3 py-1.5 text-xs font-medium text-muted-foreground">
        {title}
      </div>
      {hint && (
        <p className="border-b px-3 py-1.5 text-[11px] text-muted-foreground">
          {hint}
        </p>
      )}
      {records.length === 0 ? (
        <p className="px-3 py-2 text-xs italic text-muted-foreground">
          {emptyHint ?? "—"}
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr className="border-b">
              <th className="px-3 py-1 text-left font-medium">Name</th>
              <th className="px-2 py-1 text-left font-medium">Type</th>
              <th className="px-2 py-1 text-left font-medium">Value</th>
              <th className="px-3 py-1 text-right font-medium">TTL</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r, i) => (
              <tr key={`${r.name}-${r.record_type}-${r.value}-${i}`}>
                <td className="px-3 py-1 font-mono">
                  {r.name}.{parentZone.replace(/\.$/, "")}
                </td>
                <td className="px-2 py-1 font-mono">{r.record_type}</td>
                <td className="px-2 py-1 font-mono">{r.value}</td>
                <td className="px-3 py-1 text-right tabular-nums">
                  {r.ttl ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

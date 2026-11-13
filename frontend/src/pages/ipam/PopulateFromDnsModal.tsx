import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertCircle, CheckCircle2, DatabaseZap, X } from "lucide-react";
import {
  dnsApi,
  formatApiError,
  ipamIoApi,
  type PopulateFromDnsBody,
  type PopulateFromDnsCommit,
  type PopulateFromDnsPreview,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { permissionGate } from "@/hooks/usePermissions";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";

type Scope = { space_id?: string; block_id?: string; subnet_id?: string };

/** #2251 — adopt an existing DNS estate into IPAM. Previews what the A / AAAA
 *  records of the chosen zones would create or link, then commits. It writes
 *  IPAM rows only: no DNS record is written, queued or re-published. */
function PopulateFromDnsModal({
  scope,
  label,
  onClose,
  onCommitted,
}: {
  scope: Scope;
  label: string;
  onClose: () => void;
  onCommitted: () => void;
}) {
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);
  const [zoneIds, setZoneIds] = useState<string[]>([]);
  const [status, setStatus] =
    useState<NonNullable<PopulateFromDnsBody["status"]>>("allocated");
  const [dynamicAction, setDynamicAction] =
    useState<NonNullable<PopulateFromDnsBody["dynamic_action"]>>("skip");
  const [preview, setPreview] = useState<PopulateFromDnsPreview | null>(null);
  const [done, setDone] = useState<PopulateFromDnsCommit | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const zonesQ = useQuery({
    queryKey: ["populate-dns-zones"],
    queryFn: async () => {
      const groups = await dnsApi.listGroups();
      const lists = await Promise.all(
        groups.map((g) => dnsApi.listZones(g.id).catch(() => [])),
      );
      return lists.flat().filter((z) => z.kind === "forward");
    },
  });

  const body = (): PopulateFromDnsBody => ({
    ...scope,
    zone_ids: zoneIds.length ? zoneIds : undefined,
    status,
    dynamic_action: dynamicAction,
  });

  async function run(kind: "preview" | "commit") {
    setBusy(true);
    setError(null);
    try {
      if (kind === "preview") {
        setPreview(await ipamIoApi.previewPopulateFromDns(body()));
      } else {
        setDone(await ipamIoApi.commitPopulateFromDns(body()));
        onCommitted();
      }
    } catch (e) {
      setError(formatApiError(e, `${kind} failed`));
    } finally {
      setBusy(false);
    }
  }

  const c = preview?.counts ?? {};
  const todo =
    (c.new ?? 0) +
    (c.link ?? 0) +
    (dynamicAction === "skip" ? 0 : (c.dynamic ?? 0));

  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="flex max-h-[90vh] w-full max-w-[95vw] flex-col rounded-lg bg-background shadow-xl focus:outline-none sm:max-w-[820px]"
        style={dialogStyle}
      >
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-center justify-between border-b p-4",
            dragHandleProps.className,
          )}
        >
          <h2 {...titleProps} className="text-base font-semibold">
            Populate IPAM from DNS: {label}
          </h2>
          <button onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 space-y-3 overflow-auto p-4 text-sm">
          {done ? (
            <div className="flex items-start gap-2 text-green-700 dark:text-green-400">
              <CheckCircle2 className="mt-0.5 h-4 w-4" />
              <span>
                Created {done.created}, linked {done.linked}, updated{" "}
                {done.updated}, left alone {done.skipped}. No DNS record was
                written.
                {done.errors.length > 0 && ` ${done.errors.length} error(s).`}
              </span>
            </div>
          ) : (
            <>
              <p className="text-xs text-muted-foreground">
                Creates IPAM addresses from A / AAAA records that already exist
                in DNS and links each to its record. It writes no DNS: nothing
                is created, changed or re-published there.
              </p>
              <fieldset>
                <legend className="mb-1 text-xs font-medium">
                  Source zones (none ticked = every forward zone you can read)
                </legend>
                <div className="max-h-32 overflow-auto rounded border p-2">
                  {(zonesQ.data ?? []).map((z) => (
                    <label
                      key={z.id}
                      className="flex items-center gap-2 text-xs"
                    >
                      <input
                        type="checkbox"
                        checked={zoneIds.includes(z.id)}
                        onChange={(e) => {
                          setPreview(null);
                          setZoneIds((cur) =>
                            e.target.checked
                              ? [...cur, z.id]
                              : cur.filter((x) => x !== z.id),
                          );
                        }}
                      />
                      <span className="font-mono">{z.name}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
              <div className="flex flex-wrap gap-4">
                <label className="text-xs">
                  <span className="mb-1 block font-medium">Status</span>
                  <select
                    aria-label="Status"
                    value={status}
                    onChange={(e) => {
                      setPreview(null);
                      setStatus(e.target.value as typeof status);
                    }}
                    className="rounded border bg-background px-2 py-1"
                  >
                    <option value="allocated">allocated</option>
                    <option value="reserved">reserved</option>
                    <option value="deprecated">deprecated</option>
                  </select>
                </label>
                <label className="text-xs">
                  <span className="mb-1 block font-medium">
                    Dynamic (DDNS / DHCP-registered) records
                  </span>
                  <select
                    aria-label="Dynamic records"
                    value={dynamicAction}
                    onChange={(e) => {
                      setPreview(null);
                      setDynamicAction(e.target.value as typeof dynamicAction);
                    }}
                    className="rounded border bg-background px-2 py-1"
                  >
                    <option value="skip">skip them</option>
                    <option value="dhcp">import as DHCP addresses</option>
                    <option value="static">import with the status above</option>
                  </select>
                </label>
              </div>
              {error && (
                <div className="flex items-start gap-2 rounded border border-red-300 bg-red-50 p-2 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
                  <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              {preview && (
                <div className="space-y-2" data-testid="populate-preview">
                  <div className="flex flex-wrap gap-3 text-xs">
                    <span>New: {c.new ?? 0}</span>
                    <span>Link existing: {c.link ?? 0}</span>
                    <span>Already linked: {c.linked ?? 0}</span>
                    <span>Conflicts: {c.conflict ?? 0}</span>
                    <span>Dynamic: {c.dynamic ?? 0}</span>
                    <span>Skipped: {c.skipped ?? 0}</span>
                    <span>Outside every subnet: {preview.outside_total}</span>
                  </div>
                  {preview.dynamic_unknown > 0 && (
                    <p className="text-xs text-muted-foreground">
                      {preview.dynamic_unknown} record(s) come from a source
                      that cannot say whether they are dynamic (AXFR / pulled
                      before this was recorded); they are treated as static.
                    </p>
                  )}
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-left text-muted-foreground">
                        <th>Address</th>
                        <th>Name</th>
                        <th>Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.items.slice(0, 200).map((i) => (
                        <tr key={i.address} className="border-t">
                          <td className="font-mono">{i.address}</td>
                          <td>{i.records.map((r) => r.fqdn).join(", ")}</td>
                          <td>
                            {i.category}
                            {i.reason && ` (${i.reason.replace(/_/g, " ")})`}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {preview.total_items > 200 && (
                    <p className="text-xs text-muted-foreground">
                      Showing 200 of {preview.total_items}; the commit covers
                      all of them.
                    </p>
                  )}
                  {preview.outside.length > 0 && (
                    <div className="text-xs">
                      <div className="font-medium">
                        Records outside every subnet (create a subnet to adopt
                        them):
                      </div>
                      {preview.outside.slice(0, 20).map((g) => (
                        <div key={g.network} className="font-mono">
                          {g.network}: {g.records} record(s)
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
        <div className="flex justify-end gap-2 border-t p-3">
          <button
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs"
          >
            Close
          </button>
          {!done && (
            <>
              <button
                disabled={busy}
                onClick={() => void run("preview")}
                className="rounded border bg-muted px-3 py-1.5 text-xs font-medium disabled:opacity-50"
              >
                {busy ? "Working…" : "Preview"}
              </button>
              <button
                disabled={busy || !preview || todo === 0}
                onClick={() => void run("commit")}
                className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
              >
                Populate IPAM
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export function PopulateFromDnsButton({
  scope,
  label,
  canWrite = true,
  onCommitted,
}: {
  scope: Scope;
  label: string;
  canWrite?: boolean;
  onCommitted: () => void;
}) {
  const [open, setOpen] = useState(false);
  const gate = permissionGate(canWrite, "Requires write permission on subnets");
  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title={gate.title ?? "Create IPAM addresses from existing DNS records"}
        disabled={gate.disabled}
        className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
      >
        <DatabaseZap className="h-3.5 w-3.5" /> Populate from DNS
      </button>
      {open && (
        <PopulateFromDnsModal
          scope={scope}
          label={label}
          onClose={() => setOpen(false)}
          onCommitted={onCommitted}
        />
      )}
    </>
  );
}

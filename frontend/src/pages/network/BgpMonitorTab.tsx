import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";

import {
  asnsApi,
  type BGPHijackDetection,
  type BGPHijackRpkiStatus,
  type BGPTrackedPrefixSource,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { cn } from "@/lib/utils";

import { errMsg, humanTime, inputCls } from "./_shared";

const SOURCE_COLOR: Record<BGPTrackedPrefixSource, string> = {
  roa: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  announced: "bg-sky-500/15 text-sky-700 dark:text-sky-400",
  both: "bg-violet-500/15 text-violet-700 dark:text-violet-400",
  manual: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
};

const RPKI_COLOR: Record<BGPHijackRpkiStatus, string> = {
  invalid: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  unknown: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  valid: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
};

function Pill({ text, cls }: { text: string; cls: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        cls,
      )}
    >
      {text}
    </span>
  );
}

export function BgpMonitorTab({
  asnId,
  asnKind,
}: {
  asnId: string;
  asnKind: string;
}) {
  const qc = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [newPrefix, setNewPrefix] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [ackTarget, setAckTarget] = useState<BGPHijackDetection | null>(null);
  const [allowTarget, setAllowTarget] = useState<BGPHijackDetection | null>(
    null,
  );

  const prefixesQ = useQuery({
    queryKey: ["bgp-tracked-prefixes", asnId],
    queryFn: () => asnsApi.listTrackedPrefixes({ asn_id: asnId }),
    enabled: !!asnId,
  });

  const hijacksQ = useQuery({
    queryKey: ["bgp-hijacks", asnId],
    queryFn: () => asnsApi.listHijacks({ asn_id: asnId, active_only: false }),
    enabled: !!asnId,
  });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["bgp-tracked-prefixes", asnId] });
    void qc.invalidateQueries({ queryKey: ["bgp-hijacks", asnId] });
  };

  const refreshM = useMutation({
    mutationFn: () => asnsApi.refreshBgp(asnId),
    onSuccess: invalidate,
    onError: (e) => setErr(errMsg(e, "BGP check failed")),
  });

  const addM = useMutation({
    mutationFn: () =>
      asnsApi.createTrackedPrefix(asnId, { prefix: newPrefix.trim() }),
    onSuccess: () => {
      setAddOpen(false);
      setNewPrefix("");
      setErr(null);
      invalidate();
    },
    onError: (e) => setErr(errMsg(e, "Could not add prefix")),
  });

  const delM = useMutation({
    mutationFn: (id: string) => asnsApi.deleteTrackedPrefix(id),
    onSuccess: invalidate,
    onError: (e) => setErr(errMsg(e, "Delete failed")),
  });

  const ackM = useMutation({
    mutationFn: (id: string) => asnsApi.acknowledgeHijack(id),
    onSuccess: () => {
      setAckTarget(null);
      invalidate();
    },
    onError: (e) => setErr(errMsg(e, "Acknowledge failed")),
  });

  const allowM = useMutation({
    mutationFn: (id: string) => asnsApi.allowlistHijackOrigin(id),
    onSuccess: () => {
      setAllowTarget(null);
      invalidate();
    },
    onError: (e) => setErr(errMsg(e, "Allowlist failed")),
  });

  const prefixes = prefixesQ.data ?? [];
  const hijacks = hijacksQ.data ?? [];

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-400">
          {err}
        </div>
      )}

      {asnKind === "private" && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
          Private ASNs have no public routing presence — BGP hijack monitoring
          only applies to public ASNs.
        </div>
      )}

      {/* Detections */}
      <section>
        <div className="mb-2 flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold">Recent hijack detections</h3>
          <HeaderButton
            variant="secondary"
            onClick={() => refreshM.mutate()}
            disabled={refreshM.isPending || asnKind === "private"}
          >
            {refreshM.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            Check BGP now
          </HeaderButton>
        </div>
        <div className="rounded-lg border">
          {hijacksQ.isLoading ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              Loading…
            </div>
          ) : hijacks.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No hijack detections. While BGP monitoring is on, the poll opens a
              row here when an unexpected origin announces a tracked prefix. It
              is switched on by the bgp_monitoring_enabled platform setting,
              through the settings API; the console has no control for it.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0] shadow-border">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">
                    Observed prefix
                  </th>
                  <th className="px-3 py-2 text-left font-medium">Origin</th>
                  <th className="px-3 py-2 text-left font-medium">Kind</th>
                  <th className="px-3 py-2 text-left font-medium">RPKI</th>
                  <th className="px-3 py-2 text-left font-medium">Severity</th>
                  <th className="px-3 py-2 text-left font-medium">Last seen</th>
                  <th className="px-3 py-2 text-left font-medium">State</th>
                  <th className="px-3 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {hijacks.map((h) => (
                  <tr
                    key={h.id}
                    className="border-b last:border-0 hover:bg-muted/20"
                  >
                    <td className="whitespace-nowrap px-3 py-2 font-mono">
                      {h.observed_prefix}
                      {h.observed_prefix !== h.tracked_prefix && (
                        <span className="ml-1 text-muted-foreground">
                          (of {h.tracked_prefix})
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono">
                      AS{h.observed_origin_asn}
                      <span className="ml-1 text-muted-foreground">
                        ≠ AS{h.expected_origin_asn}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {h.detection_kind === "more_specific"
                        ? "more-specific"
                        : "exact"}
                    </td>
                    <td className="px-3 py-2">
                      <Pill
                        text={h.rpki_status}
                        cls={RPKI_COLOR[h.rpki_status]}
                      />
                    </td>
                    <td className="px-3 py-2 uppercase">{h.severity}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {humanTime(h.last_seen_at)}
                    </td>
                    <td className="px-3 py-2">
                      {h.resolved_at ? (
                        <span className="text-muted-foreground">resolved</span>
                      ) : h.acknowledged ? (
                        <span className="text-muted-foreground">acked</span>
                      ) : (
                        <span className="text-rose-600 dark:text-rose-400">
                          active
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right">
                      {!h.resolved_at && !h.acknowledged && (
                        <div className="flex justify-end gap-1">
                          <button
                            className="rounded p-1 hover:bg-muted"
                            title="Acknowledge"
                            onClick={() => setAckTarget(h)}
                          >
                            <ShieldCheck className="h-3.5 w-3.5" />
                          </button>
                          <button
                            className="rounded px-1.5 py-1 text-[10px] hover:bg-muted"
                            title="Mark this origin as expected (allowlist)"
                            onClick={() => setAllowTarget(h)}
                          >
                            Allowlist
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {/* Tracked prefixes */}
      <section>
        <div className="mb-2 flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold">Tracked prefixes</h3>
          <HeaderButton
            variant="primary"
            onClick={() => {
              setErr(null);
              setAddOpen(true);
            }}
          >
            <Plus className="h-3.5 w-3.5" /> Track prefix
          </HeaderButton>
        </div>
        <div className="rounded-lg border">
          {prefixesQ.isLoading ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              Loading…
            </div>
          ) : prefixes.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No tracked prefixes. The poll auto-populates these from RPKI ROAs
              and RIPEstat announced-prefixes; you can also add one manually.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0] shadow-border">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Prefix</th>
                  <th className="px-3 py-2 text-left font-medium">Source</th>
                  <th className="px-3 py-2 text-left font-medium">
                    Allowed origins
                  </th>
                  <th className="px-3 py-2 text-left font-medium">
                    Last checked
                  </th>
                  <th className="px-3 py-2 text-right font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {prefixes.map((p) => (
                  <tr
                    key={p.id}
                    className="border-b last:border-0 hover:bg-muted/20"
                  >
                    <td className="whitespace-nowrap px-3 py-2 font-mono">
                      {p.prefix}
                    </td>
                    <td className="px-3 py-2">
                      <Pill text={p.source} cls={SOURCE_COLOR[p.source]} />
                    </td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">
                      {p.allowed_origins.length
                        ? p.allowed_origins.map((a) => `AS${a}`).join(", ")
                        : "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {humanTime(p.last_checked_at)}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        className="rounded p-1 hover:bg-muted"
                        title="Stop tracking"
                        onClick={() => delM.mutate(p.id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {addOpen && (
        <Modal title="Track a prefix" onClose={() => setAddOpen(false)}>
          <div className="space-y-3 p-4">
            <label className="block text-xs font-medium">
              Prefix (CIDR)
              <input
                className={cn(inputCls, "mt-1")}
                placeholder="192.0.2.0/24"
                value={newPrefix}
                onChange={(e) => setNewPrefix(e.target.value)}
              />
            </label>
            <p className="text-xs text-muted-foreground">
              Manually tracked prefixes are never auto-removed by the reconcile
              sweep. The expected origin is this ASN's number.
            </p>
            <div className="flex justify-end gap-2">
              <HeaderButton
                variant="secondary"
                onClick={() => setAddOpen(false)}
              >
                Cancel
              </HeaderButton>
              <HeaderButton
                variant="primary"
                onClick={() => addM.mutate()}
                disabled={addM.isPending || !newPrefix.trim()}
              >
                {addM.isPending ? "Adding…" : "Add"}
              </HeaderButton>
            </div>
          </div>
        </Modal>
      )}

      {ackTarget && (
        <ConfirmModal
          open
          title="Acknowledge detection"
          message={`Suppress the alert for AS${ackTarget.observed_origin_asn} announcing ${ackTarget.observed_prefix}? This mutes the alert without waiting for the announcement to delist.`}
          confirmLabel="Acknowledge"
          onClose={() => setAckTarget(null)}
          onConfirm={() => ackM.mutate(ackTarget.id)}
        />
      )}

      {allowTarget && (
        <ConfirmModal
          open
          title="Allowlist expected origin"
          message={`Mark AS${allowTarget.observed_origin_asn} as an EXPECTED additional origin for ${allowTarget.tracked_prefix}? Future announcements from this origin will no longer fire, and this detection is acknowledged.`}
          confirmLabel="Allowlist origin"
          onClose={() => setAllowTarget(null)}
          onConfirm={() => allowM.mutate(allowTarget.id)}
        />
      )}
    </div>
  );
}

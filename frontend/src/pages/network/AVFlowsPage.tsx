import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AudioLines, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  avApi,
  formatApiError,
  ipamApi,
  multicastApi,
  type AVFlow,
  type AVFlowSource,
  type AVFlowUpsert,
  type AVProtocol,
  type AVReservedRange,
  type AVReservedRangeCreate,
  type AVReservedRangeUpdate,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Pager } from "@/components/ui/pager";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";

// AV over IP (issue #540, part of #543). Two operator surfaces on one
// page because they only make sense together: the flows are the AV
// identity stamped onto multicast groups, and the reserved ranges are
// the address plan those flows are checked against.

const PAGE_SIZE = 50;

const FLOW_SOURCE_LABELS: Record<string, string> = {
  manual: "Manual",
  mdns: "mDNS discovery",
  nmos: "NMOS IS-04",
};

// ── Page ─────────────────────────────────────────────────────────────

export function AVFlowsPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const avEnabled = enabled("network.av");
  // ``enabled()`` answers true while the module set is still loading, so
  // data queries wait for ``ready`` too — otherwise a hard page load
  // fires one request that 404s when the module is actually off.
  const canQuery = ready && avEnabled;
  const perms = usePermissions();
  const canWrite = perms.can("write", "av_flow");
  const canDelete = perms.can("delete", "av_flow");

  const [page, setPage] = useState(1);
  const [protocolFilter, setProtocolFilter] = useState("");
  const [ptpFilter, setPtpFilter] = useState("");
  const [search, setSearch] = useState("");

  const [flowModal, setFlowModal] = useState<
    { mode: "create" } | { mode: "edit"; flow: AVFlow } | null
  >(null);
  const [deleteFlow, setDeleteFlow] = useState<AVFlow | null>(null);
  const [rangeModal, setRangeModal] = useState<
    { mode: "create" } | { mode: "edit"; range: AVReservedRange } | null
  >(null);
  const [deleteRange, setDeleteRange] = useState<AVReservedRange | null>(null);

  const presetsQ = useQuery({
    queryKey: ["av-presets"],
    queryFn: avApi.presets,
    enabled: canQuery,
    staleTime: 5 * 60_000,
  });
  const protocols = presetsQ.data?.protocols ?? [];

  // Only a fully numeric, in-range value becomes a filter; a partial
  // entry ("2") is still valid so the query re-runs as the operator types.
  const ptpDomain =
    ptpFilter.trim() !== "" && /^\d+$/.test(ptpFilter.trim())
      ? Number(ptpFilter.trim())
      : undefined;

  const flowsQ = useQuery({
    queryKey: ["av-flows", page, protocolFilter, ptpDomain ?? "", search],
    queryFn: () =>
      avApi.listFlows({
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        av_protocol: protocolFilter || undefined,
        ptp_domain: ptpDomain,
        q: search.trim() || undefined,
      }),
    enabled: canQuery,
  });
  const flows = flowsQ.data?.items ?? [];
  const total = flowsQ.data?.total ?? 0;

  const rangesQ = useQuery({
    queryKey: ["av-reserved-ranges"],
    queryFn: () => avApi.listReservedRanges(),
    enabled: canQuery,
  });
  const ranges = rangesQ.data ?? [];

  const deleteFlowMut = useMutation({
    mutationFn: (groupId: string) => avApi.removeFlow(groupId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["av-flows"] });
      setDeleteFlow(null);
    },
  });

  const deleteRangeMut = useMutation({
    mutationFn: (id: string) => avApi.removeReservedRange(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["av-reserved-ranges"] });
      setDeleteRange(null);
    },
  });

  function protocolLabel(id: string): string {
    return protocols.find((p) => p.av_protocol === id)?.label ?? id;
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <AudioLines className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">AV over IP</h1>
              <span className="text-xs text-muted-foreground">
                {total} flow{total === 1 ? "" : "s"} · {ranges.length} reserved
                range{ranges.length === 1 ? "" : "s"}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              Audio/video-over-IP identity on top of the multicast registry.
              Stamping a group as a Dante / AES67 / SMPTE ST 2110 / NDI flow
              records its label and PTP clock domain; reserved ranges declare
              which slice of the multicast plan belongs to which protocol, so
              allocations can be checked against the studio address plan.
              Registry only — nothing here talks to a device.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={
                flowsQ.isFetching || rangesQ.isFetching ? "animate-spin" : ""
              }
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["av-flows"] });
                qc.invalidateQueries({ queryKey: ["av-reserved-ranges"] });
              }}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              disabled={!canWrite}
              title={
                canWrite ? undefined : "Requires write permission on AV flows"
              }
              onClick={() => setFlowModal({ mode: "create" })}
            >
              New flow
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 space-y-6 overflow-auto p-6">
        {/* ── AV flows ─────────────────────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">AV flows</h2>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={protocolFilter}
                onChange={(e) => {
                  setProtocolFilter(e.target.value);
                  setPage(1);
                }}
                className={filterCls}
                aria-label="Filter by AV protocol"
              >
                <option value="">All protocols</option>
                {protocols.map((p) => (
                  <option key={p.av_protocol} value={p.av_protocol}>
                    {p.label}
                  </option>
                ))}
              </select>
              <input
                value={ptpFilter}
                onChange={(e) => {
                  setPtpFilter(e.target.value);
                  setPage(1);
                }}
                inputMode="numeric"
                placeholder="PTP domain"
                className={`${filterCls} w-28`}
                aria-label="Filter by PTP domain"
              />
              <input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="Search flow label / group name…"
                className={`${filterCls} w-64`}
                aria-label="Search AV flows"
              />
            </div>
            <div className="ml-auto">
              <Pager
                page={page}
                total={total}
                pageSize={PAGE_SIZE}
                onChange={setPage}
              />
            </div>
          </div>

          <div className="rounded-lg border">
            {flows.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {flowsQ.isLoading
                  ? "Loading AV flows…"
                  : "No AV flows recorded. Stamp a multicast group as an AV flow to start documenting the plant."}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[900px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Group
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Flow label
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Protocol
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        PTP domain
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Source
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Application
                      </th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {flows.map((f) => (
                      <tr key={f.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2">
                          <div className="font-mono text-[12px]">
                            {f.group_address}
                          </div>
                          <div className="text-[11px] text-muted-foreground">
                            {f.group_name}
                          </div>
                        </td>
                        <td className="px-3 py-2">{f.av_flow_label || "—"}</td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {protocolLabel(f.av_protocol)}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {f.ptp_domain === null ? (
                            // Advisory conformity finding
                            // (av_flow_no_ptp_domain): AV streams without a
                            // declared clock domain can't be reasoned about.
                            <span className="inline-flex rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-700 dark:text-amber-400">
                              no PTP domain
                            </span>
                          ) : (
                            <span className="font-mono">{f.ptp_domain}</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {FLOW_SOURCE_LABELS[f.seen_via] ?? f.seen_via}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {f.group_application || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            type="button"
                            disabled={!canWrite}
                            onClick={() =>
                              setFlowModal({ mode: "edit", flow: f })
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
                            title="Edit AV flow"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canDelete}
                            onClick={() => setDeleteFlow(f)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                            title="Remove AV flow"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        {/* ── Reserved ranges ──────────────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">Reserved ranges</h2>
            <p className="min-w-0 flex-1 text-xs text-muted-foreground">
              Which multicast slice belongs to which protocol. Exclusive ranges
              conflict with anything else; shared ones only advise.
            </p>
            <HeaderButton
              icon={Plus}
              disabled={!canWrite}
              title={
                canWrite ? undefined : "Requires write permission on AV flows"
              }
              onClick={() => setRangeModal({ mode: "create" })}
            >
              New range
            </HeaderButton>
          </div>

          <div className="rounded-lg border">
            {ranges.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {rangesQ.isLoading
                  ? "Loading reserved ranges…"
                  : "No reserved ranges declared. Until a range exists there is nothing for the allocation guard or the AV conformity checks to compare against."}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[800px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        CIDR
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Protocol
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Name
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Mode
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Description
                      </th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {ranges.map((r) => (
                      <tr key={r.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {r.cidr}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {protocolLabel(r.av_protocol)}
                        </td>
                        <td className="px-3 py-2">
                          {r.name || "—"}
                          {r.vlan_id && (
                            <span className="ml-1 inline-flex rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-700 dark:text-sky-400">
                              VLAN-scoped
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {r.exclusive ? (
                            <span className="inline-flex rounded bg-violet-500/10 px-1.5 py-0.5 text-[11px] text-violet-700 dark:text-violet-400">
                              exclusive
                            </span>
                          ) : (
                            <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                              shared
                            </span>
                          )}
                        </td>
                        <td
                          className="max-w-md truncate px-3 py-2 text-muted-foreground"
                          title={r.description}
                        >
                          {r.description || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            type="button"
                            disabled={!canWrite}
                            onClick={() =>
                              setRangeModal({ mode: "edit", range: r })
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
                            title="Edit reserved range"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canDelete}
                            onClick={() => setDeleteRange(r)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                            title="Delete reserved range"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      </div>

      {flowModal && (
        <FlowModal
          mode={flowModal.mode}
          flow={flowModal.mode === "edit" ? flowModal.flow : null}
          protocols={protocols.map((p) => ({
            id: p.av_protocol,
            label: p.label,
          }))}
          flowSources={presetsQ.data?.flow_sources ?? []}
          ptpMin={presetsQ.data?.ptp_domain_min ?? 0}
          ptpMax={presetsQ.data?.ptp_domain_max ?? 255}
          onClose={() => setFlowModal(null)}
        />
      )}
      {rangeModal && (
        <RangeModal
          mode={rangeModal.mode}
          range={rangeModal.mode === "edit" ? rangeModal.range : null}
          protocols={protocols}
          onClose={() => setRangeModal(null)}
        />
      )}
      <ConfirmModal
        open={deleteFlow !== null}
        title="Remove AV flow"
        message={
          <>
            Remove the AV identity from{" "}
            <span className="font-mono">{deleteFlow?.group_address}</span>? The
            multicast group itself is kept — it simply stops being an AV flow.
          </>
        }
        tone="destructive"
        confirmLabel="Remove"
        loading={deleteFlowMut.isPending}
        onConfirm={() =>
          deleteFlow && deleteFlowMut.mutate(deleteFlow.group_id)
        }
        onClose={() => setDeleteFlow(null)}
      />
      <ConfirmModal
        open={deleteRange !== null}
        title="Delete reserved range"
        message={
          <>
            Undeclare <span className="font-mono">{deleteRange?.cidr}</span>?
            Nothing cascades — groups and flows inside the range are untouched,
            they just stop being checkable against it.
          </>
        }
        tone="destructive"
        confirmLabel="Delete"
        loading={deleteRangeMut.isPending}
        onConfirm={() => deleteRange && deleteRangeMut.mutate(deleteRange.id)}
        onClose={() => setDeleteRange(null)}
      />
    </div>
  );
}

// ── Flow create / edit ───────────────────────────────────────────────

function FlowModal({
  mode,
  flow,
  protocols,
  flowSources,
  ptpMin,
  ptpMax,
  onClose,
}: {
  mode: "create" | "edit";
  flow: AVFlow | null;
  protocols: { id: string; label: string }[];
  flowSources: string[];
  ptpMin: number;
  ptpMax: number;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const multicastEnabled = enabled("network.multicast");

  const [groupId, setGroupId] = useState(flow?.group_id ?? "");
  const [groupSearch, setGroupSearch] = useState("");
  const [protocol, setProtocol] = useState<string>(
    flow?.av_protocol ?? protocols[0]?.id ?? "dante",
  );
  const [label, setLabel] = useState(flow?.av_flow_label ?? "");
  const [ptp, setPtp] = useState(
    flow?.ptp_domain === null || flow?.ptp_domain === undefined
      ? ""
      : String(flow.ptp_domain),
  );
  const [seenVia, setSeenVia] = useState<string>(flow?.seen_via ?? "manual");
  const [notes, setNotes] = useState(flow?.notes ?? "");
  const [error, setError] = useState("");

  // Only needed to pick a target in create mode. Gated on the multicast
  // module because /multicast/groups 404s when it is off.
  const groupsQ = useQuery({
    queryKey: ["multicast-groups", "av-flow-picker", groupSearch],
    queryFn: () =>
      multicastApi.list({
        limit: 100,
        search: groupSearch.trim() || undefined,
      }),
    enabled: mode === "create" && ready && multicastEnabled,
    staleTime: 30_000,
  });
  const groups = groupsQ.data?.items ?? [];

  const mut = useMutation({
    mutationFn: () => {
      const body: AVFlowUpsert = {
        av_protocol: protocol as AVProtocol,
        av_flow_label: label,
        // The PUT has full-document semantics: an empty field means the
        // operator cleared the clock domain, not "leave it alone".
        ptp_domain: ptp.trim() === "" ? null : Number(ptp.trim()),
        seen_via: seenVia as AVFlowSource,
        notes,
      };
      return avApi.upsertFlow(groupId, body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["av-flows"] });
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Failed to save AV flow")),
  });

  const ptpInvalid =
    ptp.trim() !== "" &&
    (!/^\d+$/.test(ptp.trim()) ||
      Number(ptp.trim()) < ptpMin ||
      Number(ptp.trim()) > ptpMax);

  return (
    <Modal
      title={mode === "create" ? "New AV flow" : "Edit AV flow"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (groupId && !ptpInvalid) mut.mutate();
        }}
        className="space-y-3"
      >
        {mode === "create" ? (
          <Field label="Multicast group">
            {ready && !multicastEnabled ? (
              <p className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
                The Multicast feature module is disabled, so there are no groups
                to stamp. Enable it under Features & Integrations first.
              </p>
            ) : (
              <>
                <input
                  className={inputCls}
                  value={groupSearch}
                  onChange={(e) => setGroupSearch(e.target.value)}
                  placeholder="Filter groups by address or name…"
                />
                <select
                  className={`${inputCls} mt-1`}
                  value={groupId}
                  onChange={(e) => setGroupId(e.target.value)}
                  required
                >
                  <option value="">Select a multicast group…</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.address}
                      {g.name ? ` — ${g.name}` : ""}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-[11px] text-muted-foreground">
                  A group that already carries an AV profile is updated in
                  place. Showing the first {groups.length} match
                  {groups.length === 1 ? "" : "es"} — narrow the filter if the
                  group you want is missing.
                </p>
              </>
            )}
          </Field>
        ) : (
          <Field label="Multicast group">
            <p className="rounded-md border bg-muted/30 px-3 py-1.5 text-sm">
              <span className="font-mono">{flow?.group_address}</span>
              {flow?.group_name ? (
                <span className="ml-2 text-xs text-muted-foreground">
                  {flow.group_name}
                </span>
              ) : null}
            </p>
          </Field>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="AV protocol">
            <select
              className={inputCls}
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
            >
              {protocols.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Flow label">
            <input
              className={inputCls}
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Cam7 program feed"
            />
          </Field>
          <Field label={`PTP domain (${ptpMin}–${ptpMax}, blank = unknown)`}>
            <input
              className={inputCls}
              inputMode="numeric"
              value={ptp}
              onChange={(e) => setPtp(e.target.value)}
              placeholder="e.g. 0"
            />
            {ptpInvalid && (
              <p className="text-[11px] text-destructive">
                Must be a whole number between {ptpMin} and {ptpMax}.
              </p>
            )}
          </Field>
          <Field label="Source">
            <select
              className={inputCls}
              value={seenVia}
              onChange={(e) => setSeenVia(e.target.value)}
            >
              {(flowSources.length ? flowSources : ["manual"]).map((s) => (
                <option key={s} value={s}>
                  {FLOW_SOURCE_LABELS[s] ?? s}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <Field label="Notes">
          <textarea
            className={`${inputCls} min-h-[70px]`}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </Field>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending || !groupId || ptpInvalid}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Reserved-range create / edit ─────────────────────────────────────

function RangeModal({
  mode,
  range,
  protocols,
  onClose,
}: {
  mode: "create" | "edit";
  range: AVReservedRange | null;
  protocols: {
    av_protocol: string;
    label: string;
    default_cidr: string | null;
  }[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [spaceId, setSpaceId] = useState(range?.space_id ?? "");
  const [cidr, setCidr] = useState(range?.cidr ?? "");
  const [protocol, setProtocol] = useState<string>(
    range?.av_protocol ?? protocols[0]?.av_protocol ?? "dante",
  );
  const [name, setName] = useState(range?.name ?? "");
  const [description, setDescription] = useState(range?.description ?? "");
  const [exclusive, setExclusive] = useState(range?.exclusive ?? true);
  const [error, setError] = useState("");

  const spacesQ = useQuery({
    queryKey: ["ipam-spaces", "all"],
    queryFn: ipamApi.listSpaces,
    enabled: mode === "create",
    staleTime: 60_000,
  });
  const spaces = spacesQ.data ?? [];

  const defaultCidr =
    protocols.find((p) => p.av_protocol === protocol)?.default_cidr ?? null;

  const mut = useMutation({
    mutationFn: () => {
      if (mode === "edit" && range) {
        const body: AVReservedRangeUpdate = {
          cidr,
          av_protocol: protocol as AVProtocol,
          name,
          description,
          exclusive,
        };
        return avApi.updateReservedRange(range.id, body);
      }
      const body: AVReservedRangeCreate = {
        space_id: spaceId,
        cidr,
        av_protocol: protocol as AVProtocol,
        name,
        description,
        exclusive,
      };
      return avApi.createReservedRange(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["av-reserved-ranges"] });
      onClose();
    },
    onError: (e) =>
      setError(formatApiError(e, "Failed to save reserved range")),
  });

  return (
    <Modal
      title={mode === "create" ? "New reserved range" : "Edit reserved range"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        {mode === "create" ? (
          <Field label="IP space">
            <select
              className={inputCls}
              value={spaceId}
              onChange={(e) => setSpaceId(e.target.value)}
              required
            >
              <option value="">Select an IP space…</option>
              {spaces.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </Field>
        ) : (
          // The backend has no re-home path: a range is scoped to the
          // space it carves up, so moving one is a delete + create.
          <p className="text-[11px] text-muted-foreground">
            The IP space of an existing range can&rsquo;t be changed — delete
            and re-create it to move it.
          </p>
        )}

        <Field label="AV protocol">
          <select
            className={inputCls}
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
          >
            {protocols.map((p) => (
              <option key={p.av_protocol} value={p.av_protocol}>
                {p.label}
              </option>
            ))}
          </select>
        </Field>

        <Field label="CIDR">
          <input
            className={`${inputCls} font-mono`}
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="e.g. 239.69.0.0/16"
            required
          />
          <p className="text-[11px] text-muted-foreground">
            Must sit inside 224.0.0.0/4 (IPv4) or ff00::/8 (IPv6), with host
            bits zeroed.
            {defaultCidr && (
              <>
                {" "}
                Vendor default for this protocol:{" "}
                <button
                  type="button"
                  onClick={() => setCidr(defaultCidr)}
                  className="font-mono underline underline-offset-2 hover:text-foreground"
                >
                  {defaultCidr}
                </button>
              </>
            )}
          </p>
        </Field>

        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Studio A Dante"
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={exclusive}
            onChange={(e) => setExclusive(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            Exclusive
            <span className="block text-[11px] text-muted-foreground">
              Another protocol allocating inside this range is a conflict. Turn
              off for a shared range, where it is only an advisory.
            </span>
          </span>
        </label>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending || !cidr || (mode === "create" && !spaceId)}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Local form primitives ────────────────────────────────────────────

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const filterCls =
  "rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}

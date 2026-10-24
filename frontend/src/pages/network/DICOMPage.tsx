import { ListEmpty, ListReadError } from "@/components/ui/list-read-error";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Pencil,
  Plus,
  RefreshCw,
  Scan,
  ShieldAlert,
  Trash2,
  Upload,
  Waypoints,
} from "lucide-react";

import {
  dicomApi,
  formatApiError,
  ipamApi,
  type DICOMAECreate,
  type DICOMAEImportColumnMap,
  type DICOMAEImportCommit,
  type DICOMAEImportPreview,
  type DICOMAEImportRequest,
  type DICOMAESource,
  type DICOMAEUpdate,
  type DICOMApplicationEntity,
  type DICOMDeviceClass,
  type DICOMPeer,
  type DICOMRole,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Pager } from "@/components/ui/pager";
import { IPAddressPicker } from "@/components/IPAddressPicker";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";

// DICOM AE Title registry (issue #723, part of #543). Registry only —
// nothing on this page opens a DICOM association, and nothing here holds
// patient data.

const PAGE_SIZE = 50;

// IANA registers 11112 as ``dicom``; 104 carries the historical
// ``acr-nema`` name and is still widely configured. Mirrors
// app.models.dicom.DICOM_DEFAULT_PORT / DICOM_LEGACY_PORT.
const DICOM_DEFAULT_PORT = 11112;
const DICOM_LEGACY_PORT = 104;

const ROLE_LABELS: Record<string, string> = {
  scp: "SCP (responder)",
  scu: "SCU (initiator)",
  both: "Both",
};

const DEVICE_CLASS_LABELS: Record<string, string> = {
  modality: "Modality",
  pacs: "PACS",
  workstation: "Workstation",
  archive: "Archive",
  router: "Router / gateway",
  worklist: "Worklist / RIS",
  printer: "Printer",
  other: "Other",
};

const SOURCE_LABELS: Record<string, string> = {
  manual: "Manual",
  import: "Import",
  echo: "C-ECHO probe",
};

// ── Page ─────────────────────────────────────────────────────────────

export function DICOMPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const dicomEnabled = enabled("network.dicom");
  // ``enabled()`` is optimistic while the module list loads, so data
  // queries wait for ``ready`` as well — a hard page load must not fire
  // a request that 404s.
  const canQuery = ready && dicomEnabled;
  const perms = usePermissions();
  const canWrite = perms.can("write", "dicom_ae");
  const canDelete = perms.can("delete", "dicom_ae");

  const [page, setPage] = useState(1);
  const [subnetFilter, setSubnetFilter] = useState("");
  const [classFilter, setClassFilter] = useState("");
  const [reservationsOnly, setReservationsOnly] = useState(false);
  const [search, setSearch] = useState("");

  const [modal, setModal] = useState<
    { mode: "create" } | { mode: "edit"; ae: DICOMApplicationEntity } | null
  >(null);
  const [del, setDel] = useState<DICOMApplicationEntity | null>(null);
  const [impactOf, setImpactOf] = useState<DICOMApplicationEntity | null>(null);
  const [peerModal, setPeerModal] = useState(false);
  const [delPeer, setDelPeer] = useState<DICOMPeer | null>(null);
  const [importOpen, setImportOpen] = useState(false);

  const subnetsQ = useQuery({
    queryKey: ["subnets", "all"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 60_000,
  });
  const subnets = subnetsQ.data ?? [];

  const aesQ = useQuery({
    queryKey: [
      "dicom-aes",
      page,
      subnetFilter,
      classFilter,
      reservationsOnly,
      search,
    ],
    queryFn: () =>
      dicomApi.listAes({
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        subnet_id: subnetFilter || undefined,
        device_class: (classFilter || undefined) as
          | DICOMDeviceClass
          | undefined,
        unbound: reservationsOnly ? true : undefined,
        q: search.trim() || undefined,
      }),
    enabled: canQuery,
  });
  const aes = aesQ.data?.items ?? [];
  const total = aesQ.data?.total ?? 0;

  const peersQ = useQuery({
    queryKey: ["dicom-peers"],
    queryFn: () => dicomApi.listPeers(),
    enabled: canQuery,
  });
  const peers = peersQ.data ?? [];

  const delMut = useMutation({
    mutationFn: (id: string) => dicomApi.removeAe(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dicom-aes"] });
      qc.invalidateQueries({ queryKey: ["dicom-peers"] });
      setDel(null);
    },
  });

  const delPeerMut = useMutation({
    mutationFn: (id: string) => dicomApi.removePeer(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dicom-peers"] });
      qc.invalidateQueries({ queryKey: ["dicom-impact"] });
      setDelPeer(null);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Scan className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">
                DICOM application entities
              </h1>
              <span className="text-xs text-muted-foreground">
                {aesQ.error ? (
                  <ListReadError
                    error={aesQ.error}
                    what="DICOM application entities"
                  />
                ) : (
                  `${total} AE${total === 1 ? "" : "s"}`
                )}{" "}
                ·{" "}
                {peersQ.error ? (
                  <ListReadError error={peersQ.error} what="associations" />
                ) : (
                  `${peers.length} association${peers.length === 1 ? "" : "s"}`
                )}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              AE Titles are unique across the whole institution by
              specification, and a duplicate breaks C-MOVE, Storage Commitment
              and Modality Worklist in ways that take days to trace. This is the
              registry that namespace usually lives in as a spreadsheet. Network
              identity only &mdash; no patient data is stored here, and nothing
              on this page opens a DICOM association.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={
                aesQ.isFetching || peersQ.isFetching ? "animate-spin" : ""
              }
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["dicom-aes"] });
                qc.invalidateQueries({ queryKey: ["dicom-peers"] });
              }}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              icon={Upload}
              disabled={!canWrite}
              title={
                canWrite ? undefined : "Requires write permission on DICOM AEs"
              }
              onClick={() => setImportOpen(true)}
            >
              Import
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              disabled={!canWrite}
              title={
                canWrite ? undefined : "Requires write permission on DICOM AEs"
              }
              onClick={() => setModal({ mode: "create" })}
            >
              New AE
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 space-y-6 overflow-auto p-6">
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={subnetFilter}
              onChange={(e) => {
                setSubnetFilter(e.target.value);
                setPage(1);
              }}
              className={`${filterCls} max-w-[16rem]`}
              aria-label="Filter by subnet"
            >
              <option value="">All subnets</option>
              {subnets.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.network}
                  {s.name ? ` — ${s.name}` : ""}
                </option>
              ))}
            </select>
            <select
              value={classFilter}
              onChange={(e) => {
                setClassFilter(e.target.value);
                setPage(1);
              }}
              className={filterCls}
              aria-label="Filter by device class"
            >
              <option value="">All classes</option>
              {Object.entries(DEVICE_CLASS_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
            <label className="flex cursor-pointer items-center gap-1.5 text-xs">
              <input
                type="checkbox"
                checked={reservationsOnly}
                onChange={(e) => {
                  setReservationsOnly(e.target.checked);
                  setPage(1);
                }}
              />
              Reservations only
            </label>
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search title / vendor / model / department…"
              className={`${filterCls} w-72`}
              aria-label="Search DICOM application entities"
            />
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
            {aes.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {aesQ.isLoading ? (
                  "Loading application entities…"
                ) : (
                  <ListEmpty
                    error={aesQ.error}
                    what="DICOM application entities"
                  >
                    No DICOM application entities recorded.
                  </ListEmpty>
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1000px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        AE Title
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Host
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Class
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Role
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Vendor / model
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Department
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Source
                      </th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {aes.map((ae) => (
                      <tr key={ae.id} className="border-b last:border-0">
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-1.5">
                            {/* The identifier operators search by, and the
                                one peers must match exactly — mono + bold
                                so case differences read at a glance. */}
                            <span className="font-mono text-[13px] font-semibold">
                              {ae.ae_title}
                            </span>
                            {ae.is_vendor_default && <DefaultTitleBadge />}
                            {ae.is_reservation && <ReservationBadge />}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {ae.address ?? (
                            <span className="text-muted-foreground">
                              unbound
                            </span>
                          )}
                          <span className="ml-1 text-[11px] text-muted-foreground">
                            :{ae.port}
                          </span>
                          {!ae.tls_enabled && <PlaintextBadge />}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {DEVICE_CLASS_LABELS[ae.device_class] ??
                            ae.device_class}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {ROLE_LABELS[ae.role] ?? ae.role}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {[ae.vendor, ae.model_name]
                            .filter(Boolean)
                            .join(" ") || "—"}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {ae.department || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {SOURCE_LABELS[ae.seen_via] ?? ae.seen_via}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            type="button"
                            onClick={() => setImpactOf(ae)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            title="What breaks if this AE moves or goes away"
                          >
                            <Waypoints className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canWrite}
                            onClick={() => setModal({ mode: "edit", ae })}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
                            title="Edit application entity"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canDelete}
                            onClick={() => setDel(ae)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                            title="Delete application entity"
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

        {/* ── Configured associations ──────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">Configured associations</h2>
            <p className="min-w-0 flex-1 text-xs text-muted-foreground">
              Directed AE&rarr;AE edges as documented by the operator, not
              observed traffic. Direction matters: an outbound edge stops
              sending when the source moves, an inbound one stops being able to
              reach the target.
            </p>
            <HeaderButton
              icon={Plus}
              disabled={!canWrite || aes.length < 2}
              title={
                !canWrite
                  ? "Requires write permission on DICOM AEs"
                  : aes.length < 2
                    ? "Register at least two application entities first"
                    : undefined
              }
              onClick={() => setPeerModal(true)}
            >
              Add association
            </HeaderButton>
          </div>
          <div className="rounded-lg border">
            {peers.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {peersQ.isLoading
                  ? "Loading associations…"
                  : "No associations documented. Without them, the blast radius of renumbering a host cannot be reported."}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[700px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Source
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Target
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Services
                      </th>
                      <th className="px-3 py-2 text-left font-medium">Notes</th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {peers.map((p) => (
                      <tr key={p.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {p.source_ae_title}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          &rarr; {p.target_ae_title}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {p.services.length ? p.services.join(", ") : "—"}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {p.notes || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            type="button"
                            disabled={!canDelete}
                            onClick={() => setDelPeer(p)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                            title="Delete association"
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

      {modal && (
        <AEModal
          mode={modal.mode}
          ae={modal.mode === "edit" ? modal.ae : null}
          onClose={() => setModal(null)}
        />
      )}
      {impactOf && (
        <ImpactModal ae={impactOf} onClose={() => setImpactOf(null)} />
      )}
      {peerModal && <PeerModal aes={aes} onClose={() => setPeerModal(false)} />}
      {importOpen && <ImportModal onClose={() => setImportOpen(false)} />}
      <ConfirmModal
        open={delPeer !== null}
        title="Delete association"
        message={
          <>
            Remove the documented association{" "}
            <span className="font-mono font-semibold">
              {delPeer?.source_ae_title} &rarr; {delPeer?.target_ae_title}
            </span>
            ? Neither application entity is touched — only the record that they
            talk to each other, which is what the impact view reads.
          </>
        }
        tone="destructive"
        confirmLabel="Delete"
        loading={delPeerMut.isPending}
        onConfirm={() => delPeer && delPeerMut.mutate(delPeer.id)}
        onClose={() => setDelPeer(null)}
      />
      <ConfirmModal
        open={del !== null}
        title="Delete DICOM application entity"
        message={
          <>
            Delete AE Title{" "}
            <span className="font-mono font-semibold">{del?.ae_title}</span>?
            The title is freed for re-use immediately &mdash; if peers across
            the estate still send to it, check the impact view first. The IPAM
            address itself is untouched.
          </>
        }
        tone="destructive"
        confirmLabel="Delete"
        loading={delMut.isPending}
        onConfirm={() => del && delMut.mutate(del.id)}
        onClose={() => setDel(null)}
      />
    </div>
  );
}

function DefaultTitleBadge() {
  return (
    <span
      className="inline-flex rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400"
      title="Still a vendor default — the most common cause of institution-wide AE Title collisions"
    >
      default
    </span>
  );
}

function ReservationBadge() {
  return (
    <span
      className="inline-flex rounded bg-violet-500/10 px-1.5 py-0.5 text-[11px] font-medium text-violet-700 dark:text-violet-400"
      title="No host bound — the title is held so it is not re-issued while peers may still send to it"
    >
      reservation
    </span>
  );
}

function PlaintextBadge() {
  return (
    <span
      className="ml-1.5 inline-flex items-center gap-0.5 rounded bg-rose-500/10 px-1.5 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-400"
      title="Not recorded as TLS-enabled — plaintext DICOM carries ePHI in the clear"
    >
      <ShieldAlert className="h-3 w-3" />
      plaintext
    </span>
  );
}

// ── Impact ───────────────────────────────────────────────────────────

function ImpactModal({
  ae,
  onClose,
}: {
  ae: DICOMApplicationEntity;
  onClose: () => void;
}) {
  const impactQ = useQuery({
    queryKey: ["dicom-impact", ae.id],
    queryFn: () => dicomApi.impact(ae.id),
  });
  const impact = impactQ.data;

  return (
    <Modal title={`Impact — ${ae.ae_title}`} onClose={onClose} wide>
      <div className="space-y-4 text-sm">
        <p className="text-xs text-muted-foreground">
          What a renumber or decommission of{" "}
          <span className="font-mono">{ae.ae_title}</span>
          {impact?.address ? ` (${impact.address})` : ""} would disturb, per the
          associations documented in this registry.
        </p>
        {impactQ.isLoading && (
          <p className="text-xs text-muted-foreground">Loading…</p>
        )}
        {impact && impact.total_peers === 0 && (
          <p className="text-xs text-muted-foreground">
            No associations documented for this AE. That means either it is
            genuinely isolated, or the estate&rsquo;s peer configuration
            hasn&rsquo;t been recorded here yet — this view can only report what
            has been documented.
          </p>
        )}
        {impact && impact.outbound.length > 0 && (
          <div className="space-y-1">
            <h3 className="text-xs font-semibold">
              Outbound — these would stop sending
            </h3>
            <ul className="space-y-0.5 text-xs">
              {impact.outbound.map((p) => (
                <li key={p.id} className="font-mono">
                  {p.source_ae_title} &rarr; {p.target_ae_title}
                  {p.services.length > 0 && (
                    <span className="ml-2 font-sans text-muted-foreground">
                      {p.services.join(", ")}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {impact && impact.inbound.length > 0 && (
          <div className="space-y-1">
            <h3 className="text-xs font-semibold">
              Inbound — these would lose their target
            </h3>
            <ul className="space-y-0.5 text-xs">
              {impact.inbound.map((p) => (
                <li key={p.id} className="font-mono">
                  {p.source_ae_title} &rarr; {p.target_ae_title}
                  {p.services.length > 0 && (
                    <span className="ml-2 font-sans text-muted-foreground">
                      {p.services.join(", ")}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="flex justify-end pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Peer association ─────────────────────────────────────────────────

function PeerModal({
  aes,
  onClose,
}: {
  aes: DICOMApplicationEntity[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [sourceId, setSourceId] = useState(aes[0]?.id ?? "");
  const [targetId, setTargetId] = useState(aes[1]?.id ?? "");
  const [services, setServices] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      dicomApi.createPeer({
        source_ae_id: sourceId,
        target_ae_id: targetId,
        // Free-form on purpose: SOP class support is open-ended, and an
        // operator documenting their estate should never be blocked on
        // our list being complete.
        services: services
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean),
        notes,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dicom-peers"] });
      qc.invalidateQueries({ queryKey: ["dicom-impact"] });
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Failed to save association")),
  });

  const sameEndpoints = sourceId !== "" && sourceId === targetId;
  const canSubmit =
    !!sourceId && !!targetId && !sameEndpoints && !mut.isPending;

  return (
    <Modal title="Document a DICOM association" onClose={onClose} wide>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) mut.mutate();
        }}
        className="space-y-3"
      >
        <p className="text-xs text-muted-foreground">
          Direction matters: record which AE <em>initiates</em> the association.
          The impact view reads outbound and inbound edges separately, because
          they break in different ways when a host moves.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Source AE (initiator)">
            <select
              className={`${inputCls} font-mono`}
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
            >
              {aes.map((ae) => (
                <option key={ae.id} value={ae.id}>
                  {ae.ae_title}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Target AE (responder)">
            <select
              className={`${inputCls} font-mono`}
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
            >
              {aes.map((ae) => (
                <option key={ae.id} value={ae.id}>
                  {ae.ae_title}
                </option>
              ))}
            </select>
          </Field>
        </div>
        {sameEndpoints && (
          <p className="text-xs text-destructive">
            An AE cannot be configured as a peer of itself.
          </p>
        )}
        <Field label="Services">
          <input
            className={inputCls}
            value={services}
            onChange={(e) => setServices(e.target.value)}
            placeholder="C-STORE, C-FIND, C-MOVE, MPPS"
          />
          <p className="text-[11px] text-muted-foreground">
            Comma-separated. Whatever this association actually carries.
          </p>
        </Field>
        <Field label="Notes">
          <textarea
            className={`${inputCls} min-h-[60px]`}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Network configuration notes"
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
            disabled={!canSubmit}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── AE-table import ──────────────────────────────────────────────────

// Fields an operator can map a CSV column onto. Mirrors
// app.services.dicom.importer.IMPORTABLE_FIELDS; ae_title is the join
// key and is the only mandatory one.
const IMPORT_FIELDS: {
  key: keyof DICOMAEImportColumnMap;
  label: string;
  required?: boolean;
}[] = [
  { key: "ae_title", label: "AE Title", required: true },
  { key: "address", label: "IP address" },
  { key: "port", label: "Port" },
  { key: "tls_enabled", label: "TLS enabled" },
  { key: "role", label: "Role" },
  { key: "device_class", label: "Device class" },
  { key: "vendor", label: "Vendor" },
  { key: "model_name", label: "Model" },
  { key: "department", label: "Department" },
  { key: "location", label: "Location" },
  { key: "notes", label: "Notes" },
];

const ACTION_CLS: Record<string, string> = {
  create: "text-emerald-700 dark:text-emerald-400",
  update: "text-sky-700 dark:text-sky-400",
  skip: "text-muted-foreground",
  error: "text-destructive",
};

function ImportModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [csvText, setCsvText] = useState("");
  const [columnMap, setColumnMap] = useState<Record<string, string>>({
    ae_title: "AE Title",
  });
  const [overwrite, setOverwrite] = useState(false);
  const [error, setError] = useState("");
  const [preview, setPreview] = useState<DICOMAEImportPreview | null>(null);
  const [committed, setCommitted] = useState<DICOMAEImportCommit | null>(null);

  const body = (): DICOMAEImportRequest => ({
    csv_text: csvText,
    column_map: Object.fromEntries(
      Object.entries(columnMap).filter(([, v]) => v.trim() !== ""),
    ) as unknown as DICOMAEImportColumnMap,
    overwrite_existing: overwrite,
  });

  const previewMut = useMutation({
    mutationFn: () => dicomApi.importPreview(body()),
    onSuccess: (res) => {
      setPreview(res);
      setCommitted(null);
      setError("");
    },
    onError: (e) => {
      setPreview(null);
      setError(formatApiError(e, "Preview failed"));
    },
  });

  const commitMut = useMutation({
    mutationFn: () => dicomApi.importCommit(body()),
    onSuccess: (res) => {
      setCommitted(res);
      setError("");
      qc.invalidateQueries({ queryKey: ["dicom-aes"] });
    },
    onError: (e) => setError(formatApiError(e, "Import failed")),
  });

  const rows = committed?.rows ?? preview?.rows ?? [];

  return (
    <Modal title="Import DICOM AE table" onClose={onClose} wide>
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Paste the estate&rsquo;s existing AE table. Rows key on the{" "}
          <strong>AE Title</strong>, not the address — that is the identity
          DICOM cares about. A blank address registers the title as a
          reservation rather than failing; a <em>supplied</em> address IPAM does
          not know is reported as a row error. Nothing is written until you
          commit.
        </p>

        <Field label="CSV">
          <textarea
            className={`${inputCls} min-h-[140px] font-mono text-xs`}
            value={csvText}
            onChange={(e) => setCsvText(e.target.value)}
            placeholder={"AE Title,IP,Port,Class\nCT1_RAD,10.30.0.5,104,CT"}
          />
        </Field>

        <div>
          <p className="mb-1 text-xs font-medium text-muted-foreground">
            Column mapping — the header text in your file for each field
          </p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            {IMPORT_FIELDS.map((f) => (
              <label key={f.key} className="block space-y-1 text-xs">
                <span className="block text-muted-foreground">
                  {f.label}
                  {f.required ? " *" : ""}
                </span>
                <input
                  className="w-full rounded-md border bg-background px-2 py-1 text-sm"
                  value={columnMap[f.key] ?? ""}
                  onChange={(e) =>
                    setColumnMap((m) => ({ ...m, [f.key]: e.target.value }))
                  }
                  placeholder={f.required ? "required" : "leave blank to skip"}
                />
              </label>
            ))}
          </div>
        </div>

        <label className="flex cursor-pointer items-start gap-2 rounded-md border p-3 text-sm">
          <input
            type="checkbox"
            checked={overwrite}
            onChange={(e) => setOverwrite(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            Overwrite existing AE Titles
            <span className="block text-[11px] text-muted-foreground">
              Off by default: an already-registered title is skipped. On, its
              mapped fields are updated — columns your file doesn&rsquo;t have
              are left alone, so a partial export can&rsquo;t blank them.
            </span>
          </span>
        </label>

        {(preview || committed) && (
          <div className="rounded-md border">
            <div className="flex flex-wrap gap-3 border-b px-3 py-2 text-xs">
              {committed ? (
                <>
                  <span className={ACTION_CLS.create}>
                    {committed.created} created
                  </span>
                  <span className={ACTION_CLS.update}>
                    {committed.updated} updated
                  </span>
                  <span className={ACTION_CLS.skip}>
                    {committed.skipped} skipped
                  </span>
                  <span className={ACTION_CLS.error}>
                    {committed.errors} errors
                  </span>
                </>
              ) : (
                preview && (
                  <>
                    <span className={ACTION_CLS.create}>
                      {preview.create_count} to create
                    </span>
                    <span className={ACTION_CLS.update}>
                      {preview.update_count} to update
                    </span>
                    <span className={ACTION_CLS.skip}>
                      {preview.skip_count} to skip
                    </span>
                    <span className={ACTION_CLS.error}>
                      {preview.error_count} errors
                    </span>
                  </>
                )
              )}
            </div>
            <div className="max-h-56 overflow-auto">
              <table className="w-full text-xs">
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.line} className="border-b last:border-0">
                      <td className="px-3 py-1 text-muted-foreground">
                        {r.line}
                      </td>
                      <td className="px-3 py-1 font-mono">{r.ae_title}</td>
                      <td className="px-3 py-1 font-mono text-muted-foreground">
                        {r.address || "—"}
                      </td>
                      <td className={`px-3 py-1 ${ACTION_CLS[r.action] ?? ""}`}>
                        {r.action}
                      </td>
                      <td className="px-3 py-1 text-muted-foreground">
                        {r.reason}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            {committed ? "Close" : "Cancel"}
          </button>
          <button
            type="button"
            onClick={() => previewMut.mutate()}
            disabled={!csvText.trim() || previewMut.isPending}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Previewing…" : "Preview"}
          </button>
          <button
            type="button"
            onClick={() => commitMut.mutate()}
            disabled={!preview || !!committed || commitMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            title={preview ? undefined : "Preview first"}
          >
            {commitMut.isPending ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Create / edit ────────────────────────────────────────────────────

function AEModal({
  mode,
  ae,
  onClose,
}: {
  mode: "create" | "edit";
  ae: DICOMApplicationEntity | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [aeTitle, setAeTitle] = useState(ae?.ae_title ?? "");
  const [ipAddressId, setIpAddressId] = useState<string | null>(
    ae?.ip_address_id ?? null,
  );
  const [ipLabel, setIpLabel] = useState<string | null>(ae?.address ?? null);
  const [port, setPort] = useState(String(ae?.port ?? DICOM_DEFAULT_PORT));
  const [tlsEnabled, setTlsEnabled] = useState(ae?.tls_enabled ?? false);
  const [role, setRole] = useState(ae?.role ?? "both");
  const [deviceClass, setDeviceClass] = useState(ae?.device_class ?? "other");
  const [vendor, setVendor] = useState(ae?.vendor ?? "");
  const [modelName, setModelName] = useState(ae?.model_name ?? "");
  const [department, setDepartment] = useState(ae?.department ?? "");
  const [location, setLocation] = useState(ae?.location ?? "");
  const [seenVia, setSeenVia] = useState(ae?.seen_via ?? "manual");
  const [notes, setNotes] = useState(ae?.notes ?? "");
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const shared = {
        ae_title: aeTitle.trim(),
        // Parse defensively: a non-numeric field would otherwise become
        // NaN, serialise to null, and hit the column's NOT NULL as an
        // opaque server error rather than a fixable form message.
        port: parsedPort ?? DICOM_DEFAULT_PORT,
        tls_enabled: tlsEnabled,
        role: role as DICOMRole,
        device_class: deviceClass as DICOMDeviceClass,
        vendor,
        model_name: modelName,
        department,
        location,
        seen_via: seenVia as DICOMAESource,
        notes,
      };
      if (mode === "edit" && ae) {
        // Send ip_address_id unconditionally, including as null — that
        // explicit null is how a retired host demotes its title to a
        // reservation, and omitting it would make "clear the anchor"
        // indistinguishable from "don't touch it".
        const body: DICOMAEUpdate = { ...shared, ip_address_id: ipAddressId };
        return dicomApi.updateAe(ae.id, body);
      }
      const body: DICOMAECreate = { ...shared, ip_address_id: ipAddressId };
      return dicomApi.createAe(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dicom-aes"] });
      qc.invalidateQueries({ queryKey: ["dicom-peers"] });
      onClose();
    },
    onError: (e) =>
      setError(formatApiError(e, "Failed to save application entity")),
  });

  // The AE value representation is capped at 16 *bytes*, and a non-ASCII
  // character costs more than one — so measure bytes, like the server.
  const titleBytes = new TextEncoder().encode(aeTitle.trim()).length;
  const titleValid = titleBytes >= 1 && titleBytes <= 16;
  const parsedPort = /^\d+$/.test(port.trim()) ? Number(port.trim()) : null;
  const portValid =
    port.trim() === "" ||
    (parsedPort !== null && parsedPort >= 1 && parsedPort <= 65535);
  const canSubmit = titleValid && portValid && !mut.isPending;

  return (
    <Modal
      title={
        mode === "create"
          ? "New DICOM application entity"
          : "Edit DICOM application entity"
      }
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) mut.mutate();
        }}
        className="space-y-3"
      >
        <Field label="AE Title">
          <input
            className={`${inputCls} font-mono`}
            value={aeTitle}
            onChange={(e) => setAeTitle(e.target.value)}
            placeholder="e.g. CT1_RADIOLOGY"
            required
          />
          <p className="text-[11px] text-muted-foreground">
            Unique across the whole institution. Up to 16 bytes ({titleBytes}{" "}
            used); spaces are legal padding, backslash and control characters
            are not. Case is significant — peers match the title exactly.
          </p>
        </Field>

        <Field label="IPAM address">
          {ipLabel && (
            <p className="text-[11px] text-muted-foreground">
              Currently: <span className="font-mono">{ipLabel}</span>
            </p>
          )}
          <IPAddressPicker
            value={ipAddressId}
            onChange={(id, label) => {
              setIpAddressId(id);
              setIpLabel(label);
            }}
          />
          <p className="text-[11px] text-muted-foreground">
            Optional. Leave it unset to register the title as a reservation — a
            name held so it is not re-issued while peers across the estate may
            still be sending to it.
          </p>
          {ipAddressId !== null && (
            <button
              type="button"
              onClick={() => {
                setIpAddressId(null);
                setIpLabel(null);
              }}
              className="text-[11px] text-muted-foreground underline hover:text-foreground"
            >
              Clear address (make this a reservation)
            </button>
          )}
        </Field>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Port">
            <input
              className={inputCls}
              inputMode="numeric"
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
            <p className="text-[11px] text-muted-foreground">
              {DICOM_DEFAULT_PORT} is the IANA-registered <code>dicom</code>{" "}
              port; {DICOM_LEGACY_PORT} is the historical <code>acr-nema</code>{" "}
              registration and is still common.
            </p>
          </Field>
          <Field label="Device class">
            <select
              className={inputCls}
              value={deviceClass}
              onChange={(e) => setDeviceClass(e.target.value)}
            >
              {Object.entries(DEVICE_CLASS_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Role">
            <select
              className={inputCls}
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              {Object.entries(ROLE_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Source">
            <select
              className={inputCls}
              value={seenVia}
              onChange={(e) => setSeenVia(e.target.value)}
            >
              {Object.entries(SOURCE_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Vendor">
            <input
              className={inputCls}
              value={vendor}
              onChange={(e) => setVendor(e.target.value)}
            />
          </Field>
          <Field label="Model">
            <input
              className={inputCls}
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
            />
          </Field>
          <Field label="Department">
            <input
              className={inputCls}
              value={department}
              onChange={(e) => setDepartment(e.target.value)}
              placeholder="e.g. Radiology"
            />
          </Field>
          <Field label="Location">
            <input
              className={inputCls}
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              placeholder="e.g. Level 2, room 214"
            />
          </Field>
        </div>

        <label className="flex cursor-pointer items-start gap-2 rounded-md border p-3 text-sm">
          <input
            type="checkbox"
            checked={tlsEnabled}
            onChange={(e) => setTlsEnabled(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            TLS enabled
            <span className="block text-[11px] text-muted-foreground">
              Records what the estate is configured to do. Plaintext DICOM
              carries ePHI in the clear, which the <code>dicom_ae_no_tls</code>{" "}
              conformity check reports on. Nothing here is verified on the wire.
            </span>
          </span>
        </label>

        <Field label="Notes">
          <textarea
            className={`${inputCls} min-h-[70px]`}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Network configuration notes"
          />
          <p className="text-[11px] text-muted-foreground">
            Network configuration only. Never record patient-identifiable
            information — this registry stores network identity.
          </p>
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
            disabled={!canSubmit}
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

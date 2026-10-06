import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  BadgeCheck,
  Download,
  FileCode,
  MapPin,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldQuestion,
  Trash2,
} from "lucide-react";

import {
  CIVIC_FIELD_GROUPS,
  E911_RULE_LABELS,
  E911_RULE_PRECEDENCE,
  E911_RULE_TARGET,
  e911Api,
  formatApiError,
  sitesApi,
  type CivicAddress,
  type E911Confidence,
  type E911Location,
  type E911RuleKind,
  type E911ValidationState,
  type ERL,
  type ERLBinding,
  type ERLCreate,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal, ModalTabs } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Pager } from "@/components/ui/pager";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";

// E911 dispatchable location (issue #972 Phase 1a).
//
// SpatiumDDI is a location SOURCE, not a 911 service provider: no call
// routing, no ALI upload, no PSAP. RAY BAUM'S Act §506 puts the
// dispatchable-location duty on the enterprise, and this page is what
// makes it achievable and auditable — which is why the banner at the top
// says so rather than leaving an operator to infer compliance.

const PAGE_SIZE = 50;

const CONFIDENCE_STYLE: Record<E911Confidence, string> = {
  observed: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  degraded: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  none: "bg-rose-500/15 text-rose-600 dark:text-rose-400",
};

const VALIDATION_STYLE: Record<E911ValidationState, string> = {
  validated: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  unvalidated: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
  rejected: "bg-rose-500/15 text-rose-600 dark:text-rose-400",
};

/** Assembled from the columns at read time, exactly as the backend and the
 *  copilot tool do — a stored one-line address would drift from the
 *  elements that are the source of truth. Interior detail first because
 *  "Room 312" is the part a dispatcher needs. */
function addressLine(erl: CivicAddress): string {
  const interior = [
    erl.bld && `Bldg ${erl.bld}`,
    erl.flr && `Floor ${erl.flr}`,
    erl.room && `Room ${erl.room}`,
    erl.unit && `Unit ${erl.unit}`,
    erl.seat && `Seat ${erl.seat}`,
  ]
    .filter(Boolean)
    .join(" ");
  const street = [erl.hno, erl.prd, erl.rd || erl.a6, erl.sts]
    .filter(Boolean)
    .join(" ");
  const locality = [erl.a3, erl.a1, erl.pc].filter(Boolean).join(", ");
  return [interior, street, locality].filter(Boolean).join(" — ");
}

function Chip({
  className,
  children,
}: {
  className: string;
  children: React.ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs ${className}`}
    >
      {children}
    </span>
  );
}

// ── Page ─────────────────────────────────────────────────────────────

type Tab = "locations" | "bindings" | "lookup";

export function E911Page() {
  const { enabled, ready } = useFeatureModules();
  const e911Enabled = enabled("network.e911");
  // ``enabled()`` is optimistic while the module list loads, so queries
  // wait for ``ready`` too — a hard page load must not fire a request
  // that 404s behind the module gate.
  const canQuery = ready && e911Enabled;
  const [tab, setTab] = useState<Tab>("locations");

  if (ready && !e911Enabled) {
    return (
      <div className="p-6">
        <h1 className="mb-2 text-xl font-semibold">
          E911 dispatchable location
        </h1>
        <p className="text-sm text-muted-foreground">
          The <code>network.e911</code> feature module is disabled. Enable it
          under Features & Integrations.
        </p>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6">
      <div className="mb-4 flex min-w-0 flex-wrap items-center gap-2">
        <h1 className="min-w-0 flex-1 text-xl font-semibold">
          E911 dispatchable location
        </h1>
      </div>

      {/* Not a decoration. The alternative is an operator inferring that
          installing this makes them compliant, which it does not. */}
      <div className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
        <p className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <span>
            SpatiumDDI is a location <strong>source</strong>, not a 911 service
            provider — it does no call routing, no ALI upload and no PSAP
            interaction. RAY BAUM'S Act §506 (47 CFR §9.16(b)) places the
            dispatchable-location duty on <strong>your organisation</strong>.
            Address validation is your E911 provider's verdict, recorded here;
            SpatiumDDI never decides it.
          </span>
        </p>
      </div>

      <ModalTabs
        tabs={[
          { key: "locations" as Tab, label: "Locations" },
          { key: "bindings" as Tab, label: "Bindings" },
          { key: "lookup" as Tab, label: "Lookup" },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === "locations" && <LocationsTab canQuery={canQuery} />}
      {tab === "bindings" && <BindingsTab canQuery={canQuery} />}
      {tab === "lookup" && <LookupTab canQuery={canQuery} />}
    </div>
  );
}

// ── Locations (ERLs) ─────────────────────────────────────────────────

function LocationsTab({ canQuery }: { canQuery: boolean }) {
  const qc = useQueryClient();
  const perms = usePermissions();
  const canWrite = perms.can("write", "e911_location");
  const canDelete = perms.can("delete", "e911_location");

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [validation, setValidation] = useState<"" | E911ValidationState>("");
  const [dispatchable, setDispatchable] = useState<"" | "yes" | "no">("");
  const [modal, setModal] = useState<
    { mode: "create" } | { mode: "edit"; erl: ERL } | null
  >(null);
  const [verdictFor, setVerdictFor] = useState<ERL | null>(null);
  const [del, setDel] = useState<ERL | null>(null);
  const [error, setError] = useState("");

  const query = useQuery({
    queryKey: ["e911-erls", page, search, validation, dispatchable],
    queryFn: () =>
      e911Api.listErls({
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        q: search || undefined,
        validation_state: validation || undefined,
        dispatchable: dispatchable === "" ? undefined : dispatchable === "yes",
      }),
    enabled: canQuery,
  });

  const remove = useMutation({
    mutationFn: (id: string) => e911Api.removeErl(id),
    onSuccess: () => {
      setDel(null);
      setError("");
      void qc.invalidateQueries({ queryKey: ["e911-erls"] });
      // Deleting an ERL cascades its bindings, so the bindings list is
      // stale too — invalidating only this tab's key would leave the other
      // tab showing rules that no longer exist.
      void qc.invalidateQueries({ queryKey: ["e911-bindings"] });
    },
    onError: (e) => setError(formatApiError(e)),
  });

  const items = query.data?.items ?? [];

  return (
    <div>
      <div className="mb-3 flex min-w-0 flex-wrap items-center gap-2">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Name, building, floor, room, street, city…"
            className="w-full rounded-md border bg-background py-1.5 pl-8 pr-2 text-sm"
          />
        </div>
        <select
          value={validation}
          onChange={(e) => {
            setValidation(e.target.value as "" | E911ValidationState);
            setPage(1);
          }}
          className="shrink-0 rounded-md border bg-background px-2 py-1.5 text-sm"
        >
          <option value="">Any validation state</option>
          <option value="validated">Validated</option>
          <option value="unvalidated">Unvalidated</option>
          <option value="rejected">Rejected</option>
        </select>
        <select
          value={dispatchable}
          onChange={(e) => {
            setDispatchable(e.target.value as "" | "yes" | "no");
            setPage(1);
          }}
          className="shrink-0 rounded-md border bg-background px-2 py-1.5 text-sm"
          title="An ERL with no building / floor / unit / room / seat detail is a street address, not a dispatchable location."
        >
          <option value="">Dispatchable: any</option>
          <option value="yes">Has interior detail</option>
          <option value="no">Street address only</option>
        </select>
        <HeaderButton onClick={() => void query.refetch()}>
          <RefreshCw className="h-4 w-4" /> Refresh
        </HeaderButton>
        <HeaderButton
          onClick={() => void e911Api.download("csv")}
          title="Every ERL and its bindings — for review, for an auditor, or to map into Cisco Emergency Responder's own bulk load"
        >
          <Download className="h-4 w-4" /> CSV
        </HeaderButton>
        <HeaderButton
          onClick={() => void e911Api.download("ios")}
          title="LLDP-MED location stanzas for you to review and apply yourself — SpatiumDDI configures no switches"
        >
          <FileCode className="h-4 w-4" /> IOS snippets
        </HeaderButton>
        {canWrite && (
          <HeaderButton
            variant="primary"
            onClick={() => setModal({ mode: "create" })}
          >
            <Plus className="h-4 w-4" /> Add location
          </HeaderButton>
        )}
      </div>

      {error && <p className="mb-2 text-sm text-rose-600">{error}</p>}

      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[56rem] text-sm">
          <thead className="bg-muted/50 text-left">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Validation</th>
              <th className="px-3 py-2">ELINs</th>
              <th className="px-3 py-2 text-right">Bindings</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {query.isLoading && (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  Loading…
                </td>
              </tr>
            )}
            {!query.isLoading && items.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  No Emergency Response Locations yet. A voice subnet with no
                  ERL carries no dispatchable location on a 911 call.
                </td>
              </tr>
            )}
            {items.map((erl) => (
              <tr key={erl.id} className="border-t">
                <td className="px-3 py-2">
                  <div className="flex items-center gap-1.5">
                    <MapPin className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <span
                      className={
                        erl.is_active
                          ? ""
                          : "text-muted-foreground line-through"
                      }
                    >
                      {erl.name}
                    </span>
                  </div>
                </td>
                <td className="break-all px-3 py-2 text-muted-foreground">
                  {addressLine(erl) || (
                    <span className="italic">no address set</span>
                  )}
                  {!erl.is_dispatchable && (
                    <Chip className="ml-2 bg-amber-500/15 text-amber-600 dark:text-amber-400">
                      street only
                    </Chip>
                  )}
                </td>
                <td className="px-3 py-2">
                  <Chip className={VALIDATION_STYLE[erl.validation_state]}>
                    {erl.validation_state}
                  </Chip>
                  {erl.validation_source && (
                    <span className="ml-1 text-xs text-muted-foreground">
                      {erl.validation_source}
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-muted-foreground">
                  {erl.elins.length ? erl.elins.join(", ") : "—"}
                </td>
                <td className="px-3 py-2 text-right tabular-nums">
                  {erl.binding_count}
                </td>
                <td className="px-3 py-2">
                  <div className="flex justify-end gap-1">
                    {canWrite && (
                      <>
                        <button
                          type="button"
                          title="Record a validation verdict from your E911 provider"
                          onClick={() => setVerdictFor(erl)}
                          className="rounded p-1 hover:bg-muted"
                        >
                          <BadgeCheck className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          title="Edit"
                          onClick={() => setModal({ mode: "edit", erl })}
                          className="rounded p-1 hover:bg-muted"
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                      </>
                    )}
                    {canDelete && (
                      <button
                        type="button"
                        title="Delete"
                        onClick={() => setDel(erl)}
                        className="rounded p-1 text-rose-600 hover:bg-muted"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pager
        page={page}
        total={query.data?.total ?? 0}
        pageSize={PAGE_SIZE}
        onChange={setPage}
      />

      {modal && (
        <ERLModal
          erl={modal.mode === "edit" ? modal.erl : null}
          onClose={() => setModal(null)}
          onSaved={() => {
            setModal(null);
            void qc.invalidateQueries({ queryKey: ["e911-erls"] });
          }}
        />
      )}
      {verdictFor && (
        <VerdictModal
          erl={verdictFor}
          onClose={() => setVerdictFor(null)}
          onSaved={() => {
            setVerdictFor(null);
            void qc.invalidateQueries({ queryKey: ["e911-erls"] });
          }}
        />
      )}
      <ConfirmModal
        open={del !== null}
        title="Delete this location?"
        message={
          del
            ? `"${del.name}" and its ${del.binding_count} binding(s) will be removed. ` +
              "Any device that resolved to it will fall back to a coarser rule, or to " +
              "no location at all."
            : ""
        }
        confirmLabel="Delete"
        tone="destructive"
        loading={remove.isPending}
        onConfirm={() => del && remove.mutate(del.id)}
        onClose={() => setDel(null)}
      />
    </div>
  );
}

// ── ERL create / edit ────────────────────────────────────────────────

function ERLModal({
  erl,
  onClose,
  onSaved,
}: {
  erl: ERL | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(erl?.name ?? "");
  // Without this the column was unreachable from the product, so the
  // `site_default` binding rule, the site filter and the copilot's site_id
  // argument could never match anything.
  const [siteId, setSiteId] = useState(erl?.site_id ?? "");
  const sites = useQuery({
    queryKey: ["sites", "e911-picker"],
    queryFn: () => sitesApi.list({ limit: 500 }),
  });
  const [civic, setCivic] = useState<CivicAddress>(() => {
    const out: CivicAddress = {};
    if (erl) {
      for (const group of CIVIC_FIELD_GROUPS) {
        for (const f of group.fields) out[f.key] = erl[f.key] ?? "";
      }
    }
    return out;
  });
  const [elins, setElins] = useState(erl?.elins.join(", ") ?? "");
  const [lat, setLat] = useState(erl?.latitude?.toString() ?? "");
  const [lon, setLon] = useState(erl?.longitude?.toString() ?? "");
  const [notes, setNotes] = useState(erl?.notes ?? "");
  const [isActive, setIsActive] = useState(erl?.is_active ?? true);
  const [error, setError] = useState("");

  const hasInterior = CIVIC_FIELD_GROUPS[0].fields.some(
    (f) => (civic[f.key] ?? "") !== "",
  );
  const pointHalfGiven = (lat === "") !== (lon === "");
  // Number("12.3x") is NaN, which JSON.stringify renders as null — so typed
  // garbage saved silently as "no point" and, on an edit, wiped a coordinate
  // that was already there.
  const pointUnparseable =
    (lat !== "" && !Number.isFinite(Number(lat))) ||
    (lon !== "" && !Number.isFinite(Number(lon)));
  const pointOutOfRange =
    (lat !== "" &&
      Number.isFinite(Number(lat)) &&
      Math.abs(Number(lat)) > 90) ||
    (lon !== "" && Number.isFinite(Number(lon)) && Math.abs(Number(lon)) > 180);
  const pointBad = pointHalfGiven || pointUnparseable || pointOutOfRange;

  const save = useMutation({
    mutationFn: () => {
      // Empty strings become nulls: the civic columns are nullable and an
      // absent element must be ABSENT from a rendered address, not present
      // and blank. Built before the spread so the object stays typed —
      // casting to Record<string, unknown> afterwards defeats the checking
      // that makes CivicAddress worth declaring.
      const cleanCivic: CivicAddress = {};
      for (const group of CIVIC_FIELD_GROUPS) {
        for (const f of group.fields) {
          const v = (civic[f.key] ?? "") as string;
          cleanCivic[f.key] = v.trim() === "" ? null : v.trim();
        }
      }
      const body: ERLCreate = {
        name: name.trim(),
        site_id: siteId || null,
        ...cleanCivic,
        elins: elins
          .split(",")
          .map((e) => e.trim())
          .filter(Boolean),
        latitude: lat === "" ? null : Number(lat),
        longitude: lon === "" ? null : Number(lon),
        notes,
        is_active: isActive,
      };
      return erl ? e911Api.updateErl(erl.id, body) : e911Api.createErl(body);
    },
    onSuccess: onSaved,
    onError: (e) => setError(formatApiError(e)),
  });

  return (
    <Modal
      title={erl ? `Edit ${erl.name}` : "New Emergency Response Location"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="space-y-4"
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-sm">
            <span className="mb-1 block font-medium">Name</span>
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Bldg A — Floor 3 — Room 312"
              className="w-full rounded-md border bg-background px-2 py-1.5"
            />
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium">Site</span>
            <select
              value={siteId}
              onChange={(e) => setSiteId(e.target.value)}
              className="w-full rounded-md border bg-background px-2 py-1.5"
              title="The building this location is in. A site_default binding resolves through it, and it is how the compliance report groups the estate."
            >
              <option value="">No site</option>
              {(sites.data?.items ?? []).map((site) => (
                <option key={site.id} value={site.id}>
                  {site.name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium">
              ELINs{" "}
              <span className="font-normal text-muted-foreground">
                (comma-separated)
              </span>
            </span>
            <input
              value={elins}
              onChange={(e) => setElins(e.target.value)}
              placeholder="+12125550199"
              className="w-full rounded-md border bg-background px-2 py-1.5"
              title="The DIDs a PSAP sees as caller-ID and can ring back. Recorded for your PS-ALI paperwork; SpatiumDDI does not allocate or lend them."
            />
          </label>
        </div>

        {erl && erl.validation_state !== "unvalidated" && (
          <p className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-xs">
            This address is {erl.validation_state}. Editing any civic element
            resets that verdict — a provider validated the <em>old</em> address.
          </p>
        )}

        {CIVIC_FIELD_GROUPS.map((group) => (
          <fieldset key={group.label} className="rounded-md border p-3">
            <legend className="px-1 text-sm font-medium">{group.label}</legend>
            {group.hint && (
              <p className="mb-2 text-xs text-muted-foreground">{group.hint}</p>
            )}
            <div className="grid gap-2 sm:grid-cols-3">
              {group.fields.map((f) => (
                <label key={f.key} className="text-xs">
                  <span className="mb-1 block text-muted-foreground">
                    {f.label}
                  </span>
                  <input
                    value={(civic[f.key] as string) ?? ""}
                    onChange={(e) =>
                      setCivic({ ...civic, [f.key]: e.target.value })
                    }
                    placeholder={f.placeholder}
                    className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
                  />
                </label>
              ))}
            </div>
          </fieldset>
        ))}

        {!hasInterior && (
          <p className="flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-xs">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600" />
            <span>
              No building, floor, unit, room or seat is set, so this is a street
              address rather than a dispatchable location. Saving is allowed — a
              street address is a legitimate site-default ERL — but RAY BAUM'S
              §506 asks for the interior detail.
            </span>
          </p>
        )}

        <fieldset className="rounded-md border p-3">
          <legend className="px-1 text-sm font-medium">
            Coordinates (optional)
          </legend>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="text-xs">
              <span className="mb-1 block text-muted-foreground">Latitude</span>
              <input
                value={lat}
                onChange={(e) => setLat(e.target.value)}
                inputMode="decimal"
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              />
            </label>
            <label className="text-xs">
              <span className="mb-1 block text-muted-foreground">
                Longitude
              </span>
              <input
                value={lon}
                onChange={(e) => setLon(e.target.value)}
                inputMode="decimal"
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              />
            </label>
          </div>
          {pointHalfGiven && (
            <p className="mt-2 text-xs text-rose-600">
              Give both or neither — half a point is not a coarse location, it
              is a wrong one.
            </p>
          )}
          {pointUnparseable && (
            <p className="mt-2 text-xs text-rose-600">
              That is not a number. Left alone it would save as "no coordinates"
              without saying so.
            </p>
          )}
          {pointOutOfRange && (
            <p className="mt-2 text-xs text-rose-600">
              Latitude is ±90 and longitude ±180.
            </p>
          )}
        </fieldset>

        <label className="text-sm">
          <span className="mb-1 block font-medium">Notes</span>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
            className="w-full rounded-md border bg-background px-2 py-1.5"
          />
        </label>

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={isActive}
            onChange={(e) => setIsActive(e.target.checked)}
          />
          Active — an inactive ERL is skipped by the resolver, which then falls
          back to a coarser rule
        </label>

        {error && <p className="text-sm text-rose-600">{error}</p>}

        <div className="flex justify-end gap-2">
          <HeaderButton type="button" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            type="submit"
            variant="primary"
            disabled={save.isPending || pointBad}
          >
            {save.isPending ? "Saving…" : "Save"}
          </HeaderButton>
        </div>
      </form>
    </Modal>
  );
}

// ── Validation verdict ───────────────────────────────────────────────

function VerdictModal({
  erl,
  onClose,
  onSaved,
}: {
  erl: ERL;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [state, setState] = useState<E911ValidationState>(erl.validation_state);
  const [source, setSource] = useState(erl.validation_source ?? "");
  const [detail, setDetail] = useState(erl.validation_detail ?? "");
  const [error, setError] = useState("");

  const save = useMutation({
    mutationFn: () =>
      e911Api.recordValidation(erl.id, {
        state,
        source: source || null,
        detail: detail || null,
      }),
    onSuccess: onSaved,
    onError: (e) => setError(formatApiError(e)),
  });

  return (
    <Modal title={`Validation verdict — ${erl.name}`} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="space-y-3"
      >
        <p className="rounded border bg-muted/40 px-2 py-1.5 text-xs text-muted-foreground">
          Record what your E911 provider said when they validated this address
          against the MSAG / NG911 LVF. SpatiumDDI makes no outbound call and
          never decides this itself — <code>unvalidated</code> means nobody has
          confirmed the address, not that it is wrong.
        </p>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Verdict</span>
          <select
            value={state}
            onChange={(e) => setState(e.target.value as E911ValidationState)}
            className="w-full rounded-md border bg-background px-2 py-1.5"
          >
            <option value="unvalidated">
              Unvalidated — nobody has checked
            </option>
            <option value="validated">
              Validated — the provider accepted it
            </option>
            <option value="rejected">Rejected — the provider refused it</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Who said so</span>
          <input
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder="RedSky Horizon / ticket NOC-1234 / 911 coordinator"
            className="w-full rounded-md border bg-background px-2 py-1.5"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Detail</span>
          <textarea
            value={detail}
            onChange={(e) => setDetail(e.target.value)}
            rows={2}
            className="w-full rounded-md border bg-background px-2 py-1.5"
          />
        </label>
        {error && <p className="text-sm text-rose-600">{error}</p>}
        <div className="flex justify-end gap-2">
          <HeaderButton type="button" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            type="submit"
            variant="primary"
            disabled={save.isPending}
          >
            {save.isPending ? "Saving…" : "Record"}
          </HeaderButton>
        </div>
      </form>
    </Modal>
  );
}

// ── Bindings ─────────────────────────────────────────────────────────

function BindingsTab({ canQuery }: { canQuery: boolean }) {
  const qc = useQueryClient();
  const perms = usePermissions();
  const canWrite = perms.can("write", "e911_location");
  const canDelete = perms.can("delete", "e911_location");

  const [page, setPage] = useState(1);
  const [kind, setKind] = useState<"" | E911RuleKind>("");
  const [creating, setCreating] = useState(false);
  const [del, setDel] = useState<ERLBinding | null>(null);
  const [error, setError] = useState("");

  const query = useQuery({
    queryKey: ["e911-bindings", page, kind],
    queryFn: () =>
      e911Api.listBindings({
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        rule_kind: kind || undefined,
      }),
    enabled: canQuery,
  });

  const remove = useMutation({
    mutationFn: (id: string) => e911Api.removeBinding(id),
    onSuccess: () => {
      setDel(null);
      void qc.invalidateQueries({ queryKey: ["e911-bindings"] });
      // binding_count on the Locations tab moves with this.
      void qc.invalidateQueries({ queryKey: ["e911-erls"] });
    },
    onError: (e) => setError(formatApiError(e)),
  });

  const items = query.data?.items ?? [];

  function targetOf(b: ERLBinding): string {
    return (
      b.mac_address ??
      b.bssid ??
      b.network_interface_id ??
      b.subnet_id ??
      b.vlan_ref_id ??
      b.ip_address_id ??
      b.site_id ??
      "—"
    );
  }

  return (
    <div>
      <p className="mb-3 text-sm text-muted-foreground">
        Rules mapping a network identity to a location,{" "}
        <strong>most specific first</strong>. The ordering is fixed in code and
        cannot be changed — an operator able to reorder it could put the site
        default above the switch port and send every ambulance to the front
        door.
      </p>

      <div className="mb-3 flex min-w-0 flex-wrap items-center gap-2">
        <select
          value={kind}
          onChange={(e) => {
            setKind(e.target.value as "" | E911RuleKind);
            setPage(1);
          }}
          className="shrink-0 rounded-md border bg-background px-2 py-1.5 text-sm"
        >
          <option value="">All rule kinds</option>
          {E911_RULE_PRECEDENCE.map((k, i) => (
            <option key={k} value={k}>
              {i + 1}. {E911_RULE_LABELS[k]}
            </option>
          ))}
        </select>
        <div className="flex-1" />
        <HeaderButton onClick={() => void query.refetch()}>
          <RefreshCw className="h-4 w-4" /> Refresh
        </HeaderButton>
        {canWrite && (
          <HeaderButton variant="primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" /> Add binding
          </HeaderButton>
        )}
      </div>

      {error && <p className="mb-2 text-sm text-rose-600">{error}</p>}

      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[48rem] text-sm">
          <thead className="bg-muted/50 text-left">
            <tr>
              <th className="px-3 py-2">#</th>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">Target</th>
              <th className="px-3 py-2">Location</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {!query.isLoading && items.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  No bindings yet — every lookup will answer{" "}
                  <code>confidence: none</code>.
                </td>
              </tr>
            )}
            {items.map((b) => (
              <tr key={b.id} className="border-t">
                <td className="px-3 py-2 tabular-nums text-muted-foreground">
                  {b.precedence}
                </td>
                <td className="px-3 py-2">
                  {E911_RULE_LABELS[b.rule_kind]}
                  {!b.is_active && (
                    <Chip className="ml-2 bg-zinc-500/15 text-zinc-600 dark:text-zinc-400">
                      inactive
                    </Chip>
                  )}
                </td>
                <td className="break-all px-3 py-2 font-mono text-xs text-muted-foreground">
                  {targetOf(b)}
                </td>
                <td className="px-3 py-2">{b.erl_name}</td>
                <td className="px-3 py-2">
                  {canDelete && (
                    <div className="flex justify-end">
                      <button
                        type="button"
                        title="Delete"
                        onClick={() => setDel(b)}
                        className="rounded p-1 text-rose-600 hover:bg-muted"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pager
        page={page}
        total={query.data?.total ?? 0}
        pageSize={PAGE_SIZE}
        onChange={setPage}
      />

      {creating && (
        <BindingModal
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            void qc.invalidateQueries({ queryKey: ["e911-bindings"] });
            void qc.invalidateQueries({ queryKey: ["e911-erls"] });
          }}
        />
      )}
      <ConfirmModal
        open={del !== null}
        title="Delete this binding?"
        message={
          del
            ? `Devices matching this ${E911_RULE_LABELS[del.rule_kind]} rule will fall ` +
              "back to a coarser rule, or to no location at all."
            : ""
        }
        confirmLabel="Delete"
        tone="destructive"
        loading={remove.isPending}
        onConfirm={() => del && remove.mutate(del.id)}
        onClose={() => setDel(null)}
      />
    </div>
  );
}

function BindingModal({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => void;
}) {
  const [erlId, setErlId] = useState("");
  const [kind, setKind] = useState<E911RuleKind>("subnet");
  const [target, setTarget] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");

  const erls = useQuery({
    queryKey: ["e911-erls", "picker"],
    queryFn: () => e911Api.listErls({ limit: 500, is_active: true }),
  });

  const save = useMutation({
    mutationFn: () =>
      e911Api.createBinding({
        erl_id: erlId,
        rule_kind: kind,
        // Exactly the one field this rule kind requires. The server refuses
        // any other combination with a 422 naming the field — a `subnet`
        // rule carrying a MAC would satisfy "exactly one target" and then
        // match nothing.
        [E911_RULE_TARGET[kind]]: target,
        notes,
      }),
    onSuccess: onSaved,
    onError: (e) => setError(formatApiError(e)),
  });

  const targetHint: Record<E911RuleKind, string> = {
    switch_port: "network_interface id — the room-level answer",
    wireless_ap:
      "BSSID (no wireless mirror carries the client→AP association yet)",
    mac: "MAC address, any separator — for a phone on a port nothing polls",
    ip: "IPAM address row id",
    subnet: "subnet id — the floor or wing",
    vlan: "VLAN row id",
    site_default: "site id — the front door, the last-resort answer",
  };

  return (
    <Modal title="New binding" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="space-y-3"
      >
        <label className="text-sm">
          <span className="mb-1 block font-medium">Location</span>
          <select
            required
            value={erlId}
            onChange={(e) => setErlId(e.target.value)}
            className="w-full rounded-md border bg-background px-2 py-1.5"
          >
            <option value="">Select an ERL…</option>
            {(erls.data?.items ?? []).map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Rule kind</span>
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as E911RuleKind);
              setTarget("");
            }}
            className="w-full rounded-md border bg-background px-2 py-1.5"
          >
            {E911_RULE_PRECEDENCE.map((k, i) => (
              <option key={k} value={k}>
                {i + 1}. {E911_RULE_LABELS[k]}
              </option>
            ))}
          </select>
          <span className="mt-1 block text-xs text-muted-foreground">
            Lower number wins. {targetHint[kind]}
          </span>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">
            {E911_RULE_TARGET[kind].replace(/_/g, " ")}
          </span>
          <input
            required
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Notes</span>
          <input
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            className="w-full rounded-md border bg-background px-2 py-1.5"
          />
        </label>
        {error && <p className="text-sm text-rose-600">{error}</p>}
        <div className="flex justify-end gap-2">
          <HeaderButton type="button" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            type="submit"
            variant="primary"
            disabled={save.isPending}
          >
            {save.isPending ? "Saving…" : "Create"}
          </HeaderButton>
        </div>
      </form>
    </Modal>
  );
}

// ── Lookup ───────────────────────────────────────────────────────────

function LookupTab({ canQuery }: { canQuery: boolean }) {
  const [ip, setIp] = useState("");
  const [mac, setMac] = useState("");
  const [chassisId, setChassisId] = useState("");
  const [portId, setPortId] = useState("");
  const [result, setResult] = useState<E911Location | null>(null);
  const [error, setError] = useState("");

  const run = useMutation({
    mutationFn: () =>
      e911Api.lookup({
        ip: ip || undefined,
        mac: mac || undefined,
        chassis_id: chassisId || undefined,
        port_id: portId || undefined,
      }),
    onSuccess: (r) => {
      setResult(r);
      setError("");
    },
    onError: (e) => {
      setResult(null);
      setError(formatApiError(e));
    },
  });

  return (
    <div className="max-w-3xl">
      <p className="mb-3 text-sm text-muted-foreground">
        What a 911 call from this device would report. Every answer carries the
        rule that matched and the evidence behind it —{" "}
        <strong>a stale precise answer is worse than a fresh coarse one</strong>
        , so a port-level location whose switch data has gone stale is refused
        rather than returned.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          run.mutate();
        }}
        className="mb-4 grid gap-2 sm:grid-cols-2"
      >
        <label className="text-sm">
          <span className="mb-1 block font-medium">IP address</span>
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="10.20.3.44"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">MAC address</span>
          <input
            value={mac}
            onChange={(e) => setMac(e.target.value)}
            placeholder="aa:bb:cc:11:22:33"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">LLDP chassis-id</span>
          <input
            value={chassisId}
            onChange={(e) => setChassisId(e.target.value)}
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">LLDP port-id</span>
          <input
            value={portId}
            onChange={(e) => setPortId(e.target.value)}
            placeholder="Gi3/0/12"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <div className="sm:col-span-2">
          <HeaderButton
            type="submit"
            variant="primary"
            disabled={!canQuery || run.isPending || (!ip && !mac && !chassisId)}
          >
            <Search className="h-4 w-4" />
            {run.isPending ? "Resolving…" : "Resolve location"}
          </HeaderButton>
        </div>
      </form>

      {error && <p className="mb-3 text-sm text-rose-600">{error}</p>}

      {result && (
        <div className="rounded-md border">
          <div className="flex flex-wrap items-center gap-2 border-b bg-muted/40 px-3 py-2">
            <Chip className={CONFIDENCE_STYLE[result.confidence]}>
              {result.confidence}
            </Chip>
            {result.rule_matched && (
              <span className="text-sm">
                matched on{" "}
                <strong>{E911_RULE_LABELS[result.rule_matched]}</strong>
              </span>
            )}
            {result.evidence_age_seconds !== null && (
              <span className="text-xs text-muted-foreground">
                evidence {result.evidence_age_seconds}s old
              </span>
            )}
          </div>

          <div className="px-3 py-3">
            {result.erl ? (
              <>
                <p className="text-base font-medium">{result.erl.name}</p>
                <p className="text-sm text-muted-foreground">
                  {addressLine(result.erl)}
                </p>
                {result.erl.elins.length > 0 && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    ELIN: {result.erl.elins.join(", ")}
                  </p>
                )}
                <div className="mt-2 flex flex-wrap gap-2">
                  <Chip
                    className={VALIDATION_STYLE[result.erl.validation_state]}
                  >
                    {result.erl.validation_state}
                  </Chip>
                  {!result.erl.is_dispatchable && (
                    <Chip className="bg-amber-500/15 text-amber-600 dark:text-amber-400">
                      street address only
                    </Chip>
                  )}
                </div>
              </>
            ) : (
              <p className="flex items-start gap-2 text-sm">
                <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
                <span>
                  No location could be resolved for this device. A 911 call from
                  it would carry no dispatchable location.
                </span>
              </p>
            )}

            {result.degraded_reason && (
              <p className="mt-3 flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-xs">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600" />
                <span>{result.degraded_reason}</span>
              </p>
            )}

            {result.evidence.length > 0 && (
              <div className="mt-3">
                <p className="mb-1 text-xs font-medium uppercase text-muted-foreground">
                  Evidence
                </p>
                <ul className="space-y-1 text-xs">
                  {result.evidence.map((e, i) => (
                    <li key={i} className="flex flex-wrap items-center gap-2">
                      <Chip
                        className={
                          e.stale
                            ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
                            : "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400"
                        }
                      >
                        {e.kind}
                      </Chip>
                      <span className="text-muted-foreground">{e.detail}</span>
                      {e.age_seconds !== null && e.window_seconds !== null && (
                        <span className="text-muted-foreground">
                          ({e.age_seconds}s old, window {e.window_seconds}s)
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

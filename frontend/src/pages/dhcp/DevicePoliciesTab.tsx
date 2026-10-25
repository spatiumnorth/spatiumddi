import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Cpu, Eye, Pencil, Plus, Trash2 } from "lucide-react";

import {
  dhcpApi,
  type DHCPDevicePolicy,
  type DHCPDevicePolicyPreview,
} from "@/lib/api";
import {
  Modal,
  Field,
  Btns,
  inputCls,
  errMsg,
  DeleteConfirmModal,
} from "./_shared";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { deletePolicyDescription } from "./devicePolicyCopy";

const KEY_BASE = "dhcp-device-policies";
const OBS_KEY = "dhcp-device-observations";

/**
 * Device Policies tab (issue #700) — fingerbank device classes compiled
 * into Kea client classes.
 *
 * The UI's main job beyond CRUD is to keep the compiled match expression
 * visible. The issue is explicit that operators must not end up debugging
 * a black box against kea-dhcp4.log, so the preview shows the generated
 * expression, the signatures behind it, the ones excluded for ambiguity,
 * and the devices currently caught — before anything is applied.
 *
 * It is also the surface that states the v1 boundary plainly: matching is
 * over signatures already observed and classified, so a policy applies
 * from a device's next renewal, not the moment it is saved.
 */
export function DevicePoliciesTab({ groupId }: { groupId: string }) {
  // #1339, #1861 — writes take write, deletes delete, on ``dhcp_client_class``.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "dhcp_client_class"),
    "Requires write permission on DHCP client classes",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "dhcp_client_class"),
    "Requires delete permission on DHCP client classes",
  );
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<DHCPDevicePolicy | null>(null);
  const [del, setDel] = useState<DHCPDevicePolicy | null>(null);
  const [preview, setPreview] = useState<DHCPDevicePolicy | null>(null);

  const { data: policies = [], isFetching } = useQuery({
    queryKey: [KEY_BASE, groupId],
    queryFn: () => dhcpApi.listDevicePolicies(groupId),
    enabled: !!groupId,
  });

  const delMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteDevicePolicy(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [KEY_BASE, groupId] });
      setDel(null);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Cpu className="h-4 w-4 shrink-0" />
            Device Policies
          </h3>
          <p className="mt-1 text-xs text-muted-foreground">
            Give devices of a given fingerprint class their own options, lease
            time and pool. Matching is over DHCP signatures already seen and
            classified on this network, so a policy takes effect from a
            device&rsquo;s next renewal &mdash; not instantly.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
          {...writeGate}
        >
          <Plus className="h-4 w-4" /> New Policy
        </button>
      </div>

      {isFetching && policies.length === 0 ? (
        <div className="text-sm text-muted-foreground">Loading&hellip;</div>
      ) : policies.length === 0 ? (
        <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
          No device policies yet. A policy turns &ldquo;printers get a short
          lease and a restricted resolver&rdquo; into a Kea client class you can
          read and override.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[54rem] text-sm">
            <thead>
              <tr className="border-b text-left text-xs uppercase text-muted-foreground">
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Device classes</th>
                <th className="px-3 py-2">Lease</th>
                <th className="px-3 py-2">Kea class</th>
                <th className="px-3 py-2">State</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="border-b last:border-0">
                  <td className="px-3 py-2">
                    <div className="font-medium">{p.name}</div>
                    {p.description && (
                      <div className="text-xs text-muted-foreground">
                        {p.description}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {p.device_classes.length === 0 ? (
                        <span className="text-xs text-muted-foreground">
                          none selected
                        </span>
                      ) : (
                        p.device_classes.map((c) => (
                          <span
                            key={c}
                            className="rounded bg-muted px-1.5 py-0.5 text-xs"
                          >
                            {c}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {p.lease_time ? `${p.lease_time}s` : "inherit"}
                  </td>
                  <td className="px-3 py-2">
                    {/* Shown because a pool's class restriction binds to this
                        exact string — the operator needs to be able to copy it. */}
                    <code className="break-all text-xs">{p.class_name}</code>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap items-center gap-1">
                      <span
                        className={`rounded px-1.5 py-0.5 text-xs ${
                          p.enabled
                            ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                            : "bg-muted text-muted-foreground"
                        }`}
                      >
                        {p.enabled ? "enabled" : "disabled"}
                      </span>
                      {p.match_override && (
                        <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-xs text-amber-600 dark:text-amber-400">
                          manual match
                        </span>
                      )}
                      {p.include_ambiguous && (
                        <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-xs text-amber-600 dark:text-amber-400">
                          ambiguous included
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1">
                      <button
                        type="button"
                        title="Preview compiled match"
                        onClick={() => setPreview(p)}
                        className="rounded p-1 hover:bg-muted"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        type="button"
                        title="Edit"
                        onClick={() => setEdit(p)}
                        className="rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                        {...writeGate}
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        type="button"
                        title="Delete"
                        onClick={() => setDel(p)}
                        className="rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                        {...deleteGate}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <DevicePolicyModal
          groupId={groupId}
          onClose={() => setShowCreate(false)}
        />
      )}
      {edit && (
        <DevicePolicyModal
          groupId={groupId}
          policy={edit}
          onClose={() => setEdit(null)}
        />
      )}
      {preview && (
        <PreviewModal policy={preview} onClose={() => setPreview(null)} />
      )}
      {del && (
        <DeleteConfirmModal
          title="Delete device policy"
          description={deletePolicyDescription(del.name, del.class_name)}
          onConfirm={() => delMut.mutate(del.id)}
          onClose={() => setDel(null)}
          isPending={delMut.isPending}
          error={delMut.isError ? errMsg(delMut.error) : null}
        />
      )}
    </div>
  );
}

/** Create / edit. Device classes come from what fingerbank has actually
 *  returned on this install — a free-text box would let an operator build a
 *  policy against a class string that never appears, which compiles to an
 *  empty expression and renders nothing at all. */
export function DevicePolicyModal({
  groupId,
  policy,
  onClose,
}: {
  groupId: string;
  policy?: DHCPDevicePolicy;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const isEdit = !!policy;
  const [name, setName] = useState(policy?.name ?? "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const [selected, setSelected] = useState<string[]>(
    policy?.device_classes ?? [],
  );
  const [leaseTime, setLeaseTime] = useState(
    policy?.lease_time != null ? String(policy.lease_time) : "",
  );
  const [optionsText, setOptionsText] = useState(
    JSON.stringify(policy?.options ?? {}, null, 2),
  );
  const [override, setOverride] = useState(policy?.match_override ?? "");
  const [includeAmbiguous, setIncludeAmbiguous] = useState(
    policy?.include_ambiguous ?? false,
  );
  const [optionsError, setOptionsError] = useState<string | null>(null);
  const [leaseError, setLeaseError] = useState<string | null>(null);

  const { data: obs } = useQuery({
    queryKey: [OBS_KEY, groupId],
    queryFn: () => dhcpApi.listDeviceObservations(groupId),
    enabled: !!groupId,
  });

  // A class that was selected before but is no longer observed must stay
  // visible and selected, or editing an existing policy would silently drop
  // it just because the last device of that kind left the network.
  const options = useMemo(() => {
    const seen = new Map<string, { count: number; score: number | null }>();
    for (const c of obs?.classes ?? [])
      seen.set(c.device_class, { count: c.device_count, score: c.best_score });
    for (const c of selected)
      if (!seen.has(c)) seen.set(c, { count: 0, score: null });
    return [...seen.entries()].sort(
      (a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]),
    );
  }, [obs, selected]);

  const mut = useMutation({
    mutationFn: (body: Partial<DHCPDevicePolicy>) =>
      isEdit
        ? dhcpApi.updateDevicePolicy(policy!.id, body)
        : dhcpApi.createDevicePolicy(groupId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [KEY_BASE, groupId] });
      onClose();
    },
  });

  // Btns renders a type="submit" button, so the fields must sit inside a
  // <form> for Enter-to-save and the click to reach this handler at all.
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    let parsedOptions: Record<string, unknown> = {};
    if (optionsText.trim()) {
      try {
        parsedOptions = JSON.parse(optionsText);
      } catch {
        setOptionsError(
          'Options must be valid JSON, e.g. {"dns-servers": "10.0.0.53"}',
        );
        return;
      }
    }
    setOptionsError(null);
    // Blank means inherit; anything else must be a whole number of seconds.
    // Number("10m") is NaN and JSON sends NaN as null, which would store the
    // typo as "inherit" with no error (#1991).
    const leaseText = leaseTime.trim();
    let lease: number | null = null;
    if (leaseText) {
      if (!/^\d+$/.test(leaseText)) {
        setLeaseError(
          "Lease time must be a whole number of seconds, e.g. 600 (not 10m). Leave blank to inherit.",
        );
        return;
      }
      lease = Number(leaseText);
    }
    setLeaseError(null);
    mut.mutate({
      name,
      description,
      enabled,
      device_classes: selected,
      lease_time: lease,
      options: parsedOptions,
      match_override: override.trim() ? override : null,
      include_ambiguous: includeAmbiguous,
    });
  };

  return (
    <Modal
      title={
        isEdit ? `Edit Device Policy — ${policy!.name}` : "New Device Policy"
      }
      onClose={onClose}
      wide
    >
      <form onSubmit={submit} className="space-y-3">
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="IoT quarantine"
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <Field
          label="Device classes"
          hint={
            obs && obs.total_devices === 0
              ? override.trim()
                ? "No fingerprints collected yet — device classes have nothing to match until passive fingerprinting is enabled. The manual match expression below applies regardless."
                : "No fingerprints collected yet — enable passive fingerprinting first, or this policy will match nothing."
              : "Classes fingerbank has returned on this network, with device counts."
          }
        >
          <div className="max-h-44 space-y-1 overflow-y-auto rounded-md border p-2">
            {options.length === 0 ? (
              <div className="text-xs text-muted-foreground">
                Nothing observed yet.
              </div>
            ) : (
              options.map(([cls, meta]) => (
                <label key={cls} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={selected.includes(cls)}
                    onChange={(e) =>
                      setSelected((prev) =>
                        e.target.checked
                          ? [...prev, cls]
                          : prev.filter((c) => c !== cls),
                      )
                    }
                  />
                  <span className="min-w-0 flex-1 truncate">{cls}</span>
                  {/* A class name alone hides the difference between an
                      identified device and a vendor-only fallback, which is
                      what a low fingerbank score means. */}
                  {meta.score != null && (
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                        meta.score < 30
                          ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
                          : "bg-muted text-muted-foreground"
                      }`}
                      title={
                        meta.score < 30
                          ? "Low confidence — fingerbank likely fell back to the MAC vendor rather than identifying the device, so this class may group unrelated hardware."
                          : "Fingerbank confidence for this class"
                      }
                    >
                      {meta.score}/100
                    </span>
                  )}
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {meta.count} device{meta.count === 1 ? "" : "s"}
                  </span>
                </label>
              ))
            )}
          </div>
        </Field>

        <Field
          label="Lease time (seconds)"
          hint="Blank inherits the scope default. A short lease is what makes a quarantine reversible."
        >
          <input
            className={inputCls}
            value={leaseTime}
            onChange={(e) => {
              setLeaseTime(e.target.value);
              setLeaseError(null);
            }}
            placeholder="600"
            inputMode="numeric"
          />
        </Field>

        {leaseError && (
          <div role="alert" className="text-xs text-destructive">
            {leaseError}
          </div>
        )}

        <Field
          label="Options (JSON)"
          hint='Delivered to matched devices, e.g. {"dns-servers": "10.0.0.53"}'
        >
          <textarea
            className={`${inputCls} h-24 font-mono text-xs`}
            value={optionsText}
            onChange={(e) => setOptionsText(e.target.value)}
          />
        </Field>
        {optionsError && (
          <div className="text-xs text-destructive">{optionsError}</div>
        )}

        <Field
          label="Manual match expression (optional)"
          hint="Overrides the compiled expression entirely. Leave blank to use the generated one — the preview always shows both."
        >
          <textarea
            className={`${inputCls} h-20 font-mono text-xs`}
            value={override}
            onChange={(e) => setOverride(e.target.value)}
            placeholder="option[60].hex == 0x4D53465420352E30"
          />
        </Field>

        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={includeAmbiguous}
            onChange={(e) => setIncludeAmbiguous(e.target.checked)}
          />
          <span>
            Include ambiguous signatures
            <span className="block text-xs text-muted-foreground">
              Signatures that devices outside the selected classes also send.
              Including them applies this policy to those devices too.
            </span>
          </span>
        </label>

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled
        </label>

        {mut.isError && (
          <div className="text-xs text-destructive">{errMsg(mut.error)}</div>
        )}
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={isEdit ? "Save" : "Create"}
          disabled={!name.trim()}
        />
      </form>
    </Modal>
  );
}

/** The anti-black-box surface the issue asks for. */
function PreviewModal({
  policy,
  onClose,
}: {
  policy: DHCPDevicePolicy;
  onClose: () => void;
}) {
  const { data, isFetching, isError, error } = useQuery({
    queryKey: [KEY_BASE, "preview", policy.id],
    queryFn: () => dhcpApi.previewDevicePolicy(policy.id),
  });

  return (
    <Modal title={`Compiled match — ${policy.name}`} onClose={onClose} wide>
      {isFetching ? (
        <div className="text-sm text-muted-foreground">Compiling&hellip;</div>
      ) : isError ? (
        <div className="text-sm text-destructive">{errMsg(error)}</div>
      ) : data ? (
        <PreviewBody data={data} />
      ) : null}
    </Modal>
  );
}

function PreviewBody({ data }: { data: DHCPDevicePolicyPreview }) {
  return (
    <div className="space-y-4 text-sm">
      {data.warnings.length > 0 && (
        <div className="space-y-1 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
          {data.warnings.map((w) => (
            <div key={w} className="flex items-start gap-2 text-xs">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Signatures" value={String(data.signature_count)} />
        <Stat
          label="Devices matched"
          value={String(data.matched_device_count)}
        />
        <Stat
          label="Ambiguous"
          value={`${data.ambiguous_signatures.length}${
            data.ambiguous_excluded ? " excluded" : ""
          }`}
        />
        <Stat label="Renders" value={data.renders ? "yes" : "no"} />
      </div>

      <div>
        <div className="mb-1 text-xs font-semibold uppercase text-muted-foreground">
          Kea match expression ({data.source})
        </div>
        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-2 font-mono text-xs">
          {data.expression || "(matches nothing — no observed signatures yet)"}
        </pre>
      </div>

      {/* The comparison is the whole reason the override is visible: without
          it, a manual expression is exactly the black box the feature exists
          to avoid. Only shown when the two actually differ. */}
      {data.source === "override" &&
        data.compiled_expression !== data.expression && (
          <div>
            <div className="mb-1 text-xs font-semibold uppercase text-muted-foreground">
              What the compiler would have generated
            </div>
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border border-dashed bg-muted/20 p-2 font-mono text-xs text-muted-foreground">
              {data.compiled_expression ||
                "(nothing — no observed signatures in the selected classes)"}
            </pre>
          </div>
        )}

      {data.signatures.length > 0 && (
        <SignatureList title="Signatures matched" rows={data.signatures} />
      )}
      {data.ambiguous_signatures.length > 0 && (
        <SignatureList
          title={
            data.ambiguous_excluded
              ? "Excluded — also sent by devices outside these classes"
              : "Ambiguous — included by your override"
          }
          rows={data.ambiguous_signatures}
        />
      )}

      {data.matched_macs.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-semibold uppercase text-muted-foreground">
            Devices currently matched
          </div>
          <div className="flex max-h-28 flex-wrap gap-1 overflow-y-auto">
            {data.matched_macs.map((m) => (
              <code key={m} className="rounded bg-muted px-1.5 py-0.5 text-xs">
                {m}
              </code>
            ))}
          </div>
          {data.matched_macs_truncated && (
            <div className="mt-1 text-xs text-muted-foreground">
              Showing {data.matched_macs.length} of {data.matched_device_count}.
            </div>
          )}
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Matching is over signatures already observed and classified. A device
        whose signature has never been seen here does not match until it has
        leased once and been classified &mdash; policies apply from the next
        renewal, not instantly.
      </p>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm font-medium">{value}</div>
    </div>
  );
}

function SignatureList({
  title,
  rows,
}: {
  title: string;
  rows: { option_55: string | null; option_60: string | null }[];
}) {
  return (
    <div>
      <div className="mb-1 text-xs font-semibold uppercase text-muted-foreground">
        {title}
      </div>
      <div className="max-h-32 overflow-auto rounded-md border">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b text-left text-muted-foreground">
              <th className="px-2 py-1">Option 55 (request list)</th>
              <th className="px-2 py-1">Option 60 (vendor class)</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => (
              <tr
                key={`${s.option_55}|${s.option_60}|${i}`}
                className="border-b last:border-0"
              >
                <td className="px-2 py-1 font-mono break-all">
                  {s.option_55 ?? (
                    <span className="italic text-muted-foreground">absent</span>
                  )}
                </td>
                <td className="px-2 py-1 font-mono break-all">
                  {s.option_60 ?? (
                    <span className="italic text-muted-foreground">absent</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

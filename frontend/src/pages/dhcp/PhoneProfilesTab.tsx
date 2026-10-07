import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Phone, Plus, Sparkles, Trash2 } from "lucide-react";

import {
  dhcpApi,
  ipamApi,
  type PhoneOption,
  type PhoneProfile,
  type PhoneProfileCreate,
  type VoIPVendor,
} from "@/lib/api";
import {
  Modal,
  Field,
  Btns,
  inputCls,
  errMsg,
  DeleteConfirmModal,
} from "./_shared";

const PROFILE_KEY_BASE = "dhcp-phone-profiles";

/**
 * Phone Profiles tab — VoIP DHCP option recipes for a server group
 * (issue #112 phase 1). Mirrors the PXE Profiles surface but flatter:
 * one vendor-class-id substring match + a curated option set, attached
 * to scopes via a M:N join. Operators seed the curated 9-vendor
 * starter pack and tweak from there, or roll their own from scratch.
 */
export function PhoneProfilesTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<PhoneProfile | null>(null);
  const [del, setDel] = useState<PhoneProfile | null>(null);

  const { data: profiles = [], isFetching } = useQuery({
    queryKey: [PROFILE_KEY_BASE, groupId],
    queryFn: () => dhcpApi.listPhoneProfiles(groupId),
    enabled: !!groupId,
  });

  const seedMut = useMutation({
    mutationFn: () => dhcpApi.seedPhoneProfileStarterPack(groupId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [PROFILE_KEY_BASE, groupId] });
    },
  });

  const delMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deletePhoneProfile(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [PROFILE_KEY_BASE, groupId] });
      setDel(null);
    },
  });

  if (!groupId) {
    return (
      <p className="p-6 text-center text-sm text-muted-foreground">
        Phone profiles are configured on the server group — attach this server
        to a group first.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          {profiles.length} phone profile{profiles.length === 1 ? "" : "s"} on
          this group.
          {isFetching && (
            <span className="ml-2 italic text-muted-foreground/70">
              refreshing…
            </span>
          )}
        </p>
        <div className="flex items-center gap-2">
          {profiles.length === 0 && (
            <button
              type="button"
              onClick={() => seedMut.mutate()}
              disabled={seedMut.isPending}
              title="Create disabled starter profiles for the 9 curated VoIP vendors. You'll need to fill in your provisioning server values before enabling each."
              className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
            >
              <Sparkles className="h-3 w-3" />
              {seedMut.isPending ? "Seeding…" : "Seed starter pack"}
            </button>
          )}
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3 w-3" /> New Phone Profile
          </button>
        </div>
      </div>
      <div className="rounded-lg border">
        {profiles.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">
            <Phone className="mx-auto mb-2 h-8 w-8 text-muted-foreground/30" />
            No phone profiles defined. Use{" "}
            <span className="font-medium">Seed starter pack</span> for the
            curated 9 vendors, or roll your own.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <th className="px-3 py-2 text-left font-medium">Profile</th>
                  <th className="px-3 py-2 text-left font-medium">Vendor</th>
                  <th className="px-3 py-2 text-left font-medium">Match</th>
                  <th className="px-3 py-2 text-left font-medium">Options</th>
                  <th className="px-3 py-2 text-left font-medium">Scopes</th>
                  <th className="px-3 py-2 text-left font-medium">State</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {profiles.map((p) => (
                  <tr key={p.id} className="border-b last:border-0">
                    <td className="px-3 py-2 font-medium">{p.name}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {p.vendor ?? "—"}
                    </td>
                    <td
                      className="px-3 py-2 font-mono text-xs text-muted-foreground"
                      title={p.vendor_class_match ?? ""}
                    >
                      {p.vendor_class_match ? (
                        <span className="rounded bg-muted px-1.5 py-0.5">
                          {`option-60 ~ "${p.vendor_class_match}"`}
                        </span>
                      ) : (
                        <span className="text-muted-foreground/60">
                          (always)
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {p.option_set.length}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {p.scope_ids.length}
                    </td>
                    <td className="px-3 py-2">
                      {p.enabled ? (
                        <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                          enabled
                        </span>
                      ) : (
                        <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                          disabled
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => setEdit(p)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground"
                        title="Edit profile"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDel(p)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive"
                        title="Delete profile"
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

      {showCreate && (
        <PhoneProfileEditorModal
          groupId={groupId}
          onClose={() => setShowCreate(false)}
        />
      )}
      {edit && (
        <PhoneProfileEditorModal
          groupId={groupId}
          profile={edit}
          onClose={() => setEdit(null)}
        />
      )}
      {del && (
        <DeleteConfirmModal
          title="Delete Phone Profile"
          description={`Delete profile "${del.name}"? Any client matching its vendor-class fence will stop receiving its option set on the next bundle push.`}
          onConfirm={() => delMut.mutate(del.id)}
          onClose={() => setDel(null)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Editor modal ───────────────────────────────────────────────────────────

function PhoneProfileEditorModal({
  groupId,
  profile,
  onClose,
}: {
  groupId: string;
  profile?: PhoneProfile;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const isEdit = !!profile;

  const { data: vendors = [] } = useQuery({
    queryKey: ["dhcp-voip-vendors"],
    queryFn: () => dhcpApi.listVoipVendors(),
    staleTime: 5 * 60 * 1000,
  });
  // Group's scopes — populates the M:N attachment picker.
  const { data: groupScopes = [] } = useQuery({
    queryKey: ["dhcp-scopes-group", groupId],
    queryFn: () => dhcpApi.listScopesByGroup(groupId),
    enabled: !!groupId,
  });
  // Subnet CIDR lookup so the picker shows "10.0.20.0/24 — voice-vlan-20"
  // instead of opaque scope names.
  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
  });
  const subnetById = useMemo(
    () => new Map(subnets.map((s) => [s.id, s])),
    [subnets],
  );

  const [name, setName] = useState(profile?.name ?? "");
  const [description, setDescription] = useState(profile?.description ?? "");
  const [enabled, setEnabled] = useState(profile?.enabled ?? true);
  const [vendor, setVendor] = useState(profile?.vendor ?? "");
  const [vendorClassMatch, setVendorClassMatch] = useState(
    profile?.vendor_class_match ?? "",
  );
  const [optionSet, setOptionSet] = useState<PhoneOption[]>(
    profile?.option_set ?? [],
  );
  const [scopeIds, setScopeIds] = useState<string[]>(profile?.scope_ids ?? []);
  const [error, setError] = useState<string | null>(null);

  // When the operator picks a vendor from the curated catalog, pre-fill
  // the vendor-class-match + option_set if they're empty (don't clobber
  // operator edits silently).
  function applyVendorRecipe(v: VoIPVendor) {
    setVendor(v.vendor);
    if (!vendorClassMatch) {
      setVendorClassMatch(v.match_hint || "");
    }
    if (optionSet.length === 0) {
      setOptionSet(
        v.options.map((o) => ({ code: o.code, name: o.name, value: "" })),
      );
    }
  }

  const saveMut = useMutation({
    mutationFn: async () => {
      const body: PhoneProfileCreate = {
        name: name.trim(),
        description,
        enabled,
        vendor: vendor.trim() || null,
        vendor_class_match: vendorClassMatch.trim() || null,
        option_set: optionSet
          .filter((o) => o.value.trim())
          .map((o) => ({ code: o.code, name: o.name ?? null, value: o.value })),
        scope_ids: scopeIds,
      };
      if (isEdit) {
        const updated = await dhcpApi.updatePhoneProfile(profile.id, body);
        await dhcpApi.setPhoneProfileScopes(profile.id, scopeIds);
        return updated;
      }
      return dhcpApi.createPhoneProfile(groupId, body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [PROFILE_KEY_BASE, groupId] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Save failed")),
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError("Profile name is required");
      return;
    }
    setError(null);
    saveMut.mutate();
  }

  function addOptionRow() {
    setOptionSet((prev) => [...prev, { code: 66, name: "", value: "" }]);
  }
  function updateOption(i: number, patch: Partial<PhoneOption>) {
    setOptionSet((prev) =>
      prev.map((o, k) => (k === i ? { ...o, ...patch } : o)),
    );
  }
  function removeOption(i: number) {
    setOptionSet((prev) => prev.filter((_, k) => k !== i));
  }

  function toggleScope(id: string) {
    setScopeIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  // If the form is fresh and there's exactly one vendor matching the
  // typed-in name, surface a hint to seed from that recipe.
  useEffect(() => {
    if (isEdit) return;
    if (!vendor) return;
    const match = vendors.find(
      (v) => v.vendor.toLowerCase() === vendor.toLowerCase(),
    );
    if (match && optionSet.length === 0 && !vendorClassMatch) {
      applyVendorRecipe(match);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vendors, vendor]);

  return (
    <Modal
      title={
        isEdit ? `Edit Phone Profile — ${profile.name}` : "New Phone Profile"
      }
      onClose={onClose}
      wide
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Polycom Voice"
              autoFocus
            />
          </Field>
          <Field label="Curated vendor (optional)">
            <select
              className={inputCls}
              value={vendor}
              onChange={(e) => {
                const v = e.target.value;
                setVendor(v);
                const recipe = vendors.find((rec) => rec.vendor === v);
                if (recipe) applyVendorRecipe(recipe);
              }}
            >
              <option value="">— custom —</option>
              {vendors.map((v) => (
                <option key={v.vendor} value={v.vendor}>
                  {v.vendor}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <Field label="Description">
          <textarea
            className={inputCls}
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Free-text notes operators see in the profile list."
          />
        </Field>

        <Field
          label="Vendor-class-id match (option 60)"
          hint="Substring match — e.g. 'Polycom' or 'yealink'. Empty = always match (rarely what you want)."
        >
          <input
            className={inputCls}
            value={vendorClassMatch}
            onChange={(e) => setVendorClassMatch(e.target.value)}
            placeholder="Polycom"
          />
        </Field>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">
              Option set
            </span>
            <button
              type="button"
              onClick={addOptionRow}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] hover:bg-accent"
            >
              <Plus className="h-3 w-3" /> Add option
            </button>
          </div>
          {optionSet.length === 0 ? (
            <p className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
              No options yet. Pick a curated vendor above to pre-fill the common
              codes, or click <span className="font-medium">Add option</span>.
            </p>
          ) : (
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full text-xs">
                <thead className="bg-muted/30">
                  <tr className="border-b">
                    <th className="px-2 py-1.5 text-left font-medium">Code</th>
                    <th className="px-2 py-1.5 text-left font-medium">
                      Name (label)
                    </th>
                    <th className="px-2 py-1.5 text-left font-medium">Value</th>
                    <th className="px-2 py-1.5"></th>
                  </tr>
                </thead>
                <tbody>
                  {optionSet.map((o, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-2 py-1">
                        <input
                          className={`${inputCls} w-20`}
                          type="number"
                          min={1}
                          max={254}
                          value={o.code}
                          onChange={(e) =>
                            updateOption(i, { code: Number(e.target.value) })
                          }
                        />
                      </td>
                      <td className="px-2 py-1">
                        <input
                          className={inputCls}
                          value={o.name ?? ""}
                          onChange={(e) =>
                            updateOption(i, { name: e.target.value })
                          }
                          placeholder="tftp-server-name"
                        />
                      </td>
                      <td className="px-2 py-1">
                        <input
                          className={inputCls}
                          value={o.value}
                          onChange={(e) =>
                            updateOption(i, { value: e.target.value })
                          }
                          placeholder="tftp.example.com"
                        />
                      </td>
                      <td className="px-2 py-1 text-right">
                        <button
                          type="button"
                          onClick={() => removeOption(i)}
                          className="rounded p-1 text-muted-foreground hover:text-destructive"
                          title="Remove this option"
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

        <Field
          label="Attached scopes"
          hint="The profile's options apply to clients leasing from any of the selected scopes (and matching the vendor-class fence)."
        >
          {groupScopes.length === 0 ? (
            <p className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
              No scopes on this group yet — create a scope first, then attach.
            </p>
          ) : (
            <div className="max-h-40 overflow-auto rounded-md border">
              {groupScopes.map((sc) => {
                const subnet = subnetById.get(sc.subnet_id);
                const checked = scopeIds.includes(sc.id);
                return (
                  <label
                    key={sc.id}
                    className="flex cursor-pointer items-center gap-2 px-2 py-1.5 text-xs hover:bg-accent"
                  >
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5"
                      checked={checked}
                      onChange={() => toggleScope(sc.id)}
                    />
                    <span className="font-mono">{subnet?.network ?? "—"}</span>
                    <span className="text-muted-foreground">{sc.name}</span>
                  </label>
                );
              })}
            </div>
          )}
        </Field>

        <Field label="Enabled">
          <label className="inline-flex cursor-pointer items-center gap-2 text-xs">
            <input
              type="checkbox"
              className="h-3.5 w-3.5"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>
              {enabled
                ? "Active — clients matching the fence get this option set."
                : "Disabled — no client-class is rendered for this profile."}
            </span>
          </label>
        </Field>

        {error && (
          <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </p>
        )}

        <Btns onClose={onClose} pending={saveMut.isPending} />
      </form>
    </Modal>
  );
}

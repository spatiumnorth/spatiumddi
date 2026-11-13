import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Copy, Eye, EyeOff, Plus, Trash2 } from "lucide-react";
import {
  settingsApi,
  type PlatformSettings,
  type SnmpV3User,
  type SnmpV3UserWrite,
  type SnmpAuthProtocol,
  type SnmpPrivProtocol,
  type SnmpVersion,
  formatApiError,
  formatDialogError,
} from "@/lib/api";
import { Toggle } from "@/components/ui/toggle";
import { cn } from "@/lib/utils";

interface Props {
  values: PlatformSettings;
  isSuperadmin: boolean;
  applianceMode: boolean;
  inputCls: string;
}

// Helpers for the tri-state community input — same shape as
// DeviceProfilingSection's fingerbank pattern.
function CommunityField({
  values,
  draft,
  setDraft,
  isSuperadmin,
  inputCls,
}: {
  values: PlatformSettings;
  draft: string | undefined;
  setDraft: (v: string | undefined) => void;
  isSuperadmin: boolean;
  inputCls: string;
}) {
  const isSet = !!values.snmp_community_set;
  const [replacing, setReplacing] = useState(false);
  const [revealing, setRevealing] = useState(false);
  const [revealPassword, setRevealPassword] = useState("");
  const [revealTotp, setRevealTotp] = useState("");
  const [revealed, setRevealed] = useState<string | null>(null);

  // Operator-driven reveal — gated server-side on password +
  // superadmin + local-auth. Every reveal (success or failure) is
  // audit-logged so abuse is visible. UI surfaces the plaintext until
  // the operator clicks Hide; we deliberately don't auto-hide on a
  // timer because the operator just typed a password to get here and
  // wants the value long enough to paste it into an NMS / snmpwalk.
  // #408 — re-confirm with a local password OR a TOTP code (SSO accounts
  // have no local password; enrol under Account → Two-factor).
  const revealMutation = useMutation({
    mutationFn: () =>
      settingsApi.revealSnmpCommunity(
        revealPassword || undefined,
        revealTotp || undefined,
      ),
    onSuccess: (data) => {
      setRevealed(data.community ?? "(no community configured)");
      setRevealing(false);
      setRevealPassword("");
      setRevealTotp("");
    },
  });

  const clearPending = isSet && draft === "";
  const showInput =
    !isSet || replacing || (draft !== undefined && draft !== "");

  return (
    <Field
      label="Community string (v2c)"
      description="Read-only community for SNMPv2c queries. Stored Fernet-encrypted server-side; the Reveal button surfaces the plaintext after a password re-confirm (every reveal is audited). ``public`` is intentionally NOT pre-seeded — leaving the field empty disables SNMP queries even when the master toggle is on."
    >
      <div className="flex flex-col items-end gap-2">
        {clearPending ? (
          <div className="flex items-center gap-2">
            <span className="rounded bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
              Pending clear — save to apply
            </span>
            <button
              type="button"
              onClick={() => setDraft(undefined)}
              disabled={!isSuperadmin}
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
            >
              Undo
            </button>
          </div>
        ) : showInput ? (
          <div className="flex items-center gap-2">
            <input
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={draft ?? ""}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={
                isSet
                  ? "(replace existing community)"
                  : "Enter community string"
              }
              disabled={!isSuperadmin}
              className={cn(inputCls, "w-96 max-w-full font-mono")}
            />
            {isSet && (
              <button
                type="button"
                onClick={() => {
                  setDraft(undefined);
                  setReplacing(false);
                }}
                disabled={!isSuperadmin}
                className="rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
                title="Cancel — keep the existing community"
              >
                Cancel
              </button>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <span className="rounded bg-emerald-500/10 px-2 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              Configured ✓
            </span>
            <button
              type="button"
              onClick={() => {
                setRevealing(true);
                setRevealed(null);
              }}
              disabled={!isSuperadmin || revealing}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
              title="Show the configured community after password re-confirm"
            >
              <Eye className="h-3 w-3" />
              Reveal
            </button>
            <button
              type="button"
              onClick={() => setReplacing(true)}
              disabled={!isSuperadmin}
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
            >
              Replace…
            </button>
            <button
              type="button"
              onClick={() => setDraft("")}
              disabled={!isSuperadmin}
              className="rounded-md border border-destructive/40 px-2 py-1 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-40"
            >
              Clear
            </button>
          </div>
        )}

        {/* Reveal — password-confirm input. Stays open until the
            mutation succeeds; failure (bad password / not
            superadmin / external-auth) surfaces the server's error
            message inline so the operator knows why. */}
        {revealing && (
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (revealPassword || revealTotp) revealMutation.mutate();
            }}
          >
            <input
              type="password"
              autoComplete="current-password"
              value={revealPassword}
              onChange={(e) => setRevealPassword(e.target.value)}
              placeholder="Password"
              className={cn(inputCls, "w-40 font-mono")}
              autoFocus
            />
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              value={revealTotp}
              onChange={(e) => setRevealTotp(e.target.value)}
              placeholder="or 6-digit code"
              className={cn(inputCls, "w-32 font-mono")}
              title="SSO accounts: enter an authenticator code instead of a password"
            />
            <button
              type="submit"
              disabled={
                (!revealPassword && !revealTotp) || revealMutation.isPending
              }
              className="rounded-md border bg-primary px-2 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
            >
              {revealMutation.isPending ? "Verifying…" : "Reveal"}
            </button>
            <button
              type="button"
              onClick={() => {
                setRevealing(false);
                setRevealPassword("");
                setRevealTotp("");
                revealMutation.reset();
              }}
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
            >
              Cancel
            </button>
          </form>
        )}
        {revealMutation.isError && (
          <span className="text-xs text-destructive">
            {formatApiError(revealMutation.error)}
          </span>
        )}

        {/* Revealed plaintext — operator-visible until they click Hide
            or navigate away. No auto-hide timer: the operator just
            password-confirmed to get here; making it disappear on a
            timer would surprise them mid-paste. */}
        {revealed !== null && (
          <div className="flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-2 py-1">
            <span className="font-mono text-xs">{revealed}</span>
            <button
              type="button"
              onClick={() => navigator.clipboard.writeText(revealed)}
              className="rounded p-1 hover:bg-accent"
              title="Copy to clipboard"
            >
              <Copy className="h-3 w-3" />
            </button>
            <button
              type="button"
              onClick={() => setRevealed(null)}
              className="rounded p-1 hover:bg-accent"
              title="Hide"
            >
              <EyeOff className="h-3 w-3" />
            </button>
          </div>
        )}
      </div>
    </Field>
  );
}

function Field({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-8 py-3">
      <div className="max-w-xl">
        <div className="text-sm font-medium">{label}</div>
        {description && (
          <div className="text-xs text-muted-foreground">{description}</div>
        )}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

// Per-row v3 user draft state. Plain object mirroring the response
// shape, plus optional ``auth_pass`` / ``priv_pass`` strings that
// represent operator-typed plaintext (only meaningful at submit time).
interface V3UserDraft {
  username: string;
  auth_protocol: SnmpAuthProtocol;
  auth_pass_set: boolean;
  // ``undefined`` = leave existing alone. ``""`` = clear. Non-empty = encrypt.
  auth_pass?: string;
  priv_protocol: SnmpPrivProtocol;
  priv_pass_set: boolean;
  priv_pass?: string;
}

function userToDraft(u: SnmpV3User): V3UserDraft {
  return {
    username: u.username,
    auth_protocol: u.auth_protocol,
    auth_pass_set: u.auth_pass_set,
    priv_protocol: u.priv_protocol,
    priv_pass_set: u.priv_pass_set,
  };
}

function draftToWrite(d: V3UserDraft): SnmpV3UserWrite {
  // None semantics: undefined → omit (leave alone); else send through.
  return {
    username: d.username,
    auth_protocol: d.auth_protocol,
    auth_pass: d.auth_pass,
    priv_protocol: d.priv_protocol,
    priv_pass: d.priv_pass,
  };
}

export function SNMPSection({
  values,
  isSuperadmin,
  applianceMode,
  inputCls,
}: Props) {
  const qc = useQueryClient();
  // Local state separate from the global form. SNMP's v3 user merge
  // semantics (per-user pass leave-alone / clear / replace) don't fit
  // the global form's flat key→value diff model, so this section has
  // its own Save button.
  const [enabled, setEnabled] = useState<boolean>(values.snmp_enabled);
  const [version, setVersion] = useState<SnmpVersion>(values.snmp_version);
  const [community, setCommunity] = useState<string | undefined>(undefined);
  const [sources, setSources] = useState<string>(
    (values.snmp_allowed_sources || []).join(", "),
  );
  const [sysContact, setSysContact] = useState<string>(
    values.snmp_sys_contact ?? "",
  );
  const [sysLocation, setSysLocation] = useState<string>(
    values.snmp_sys_location ?? "",
  );
  const [users, setUsers] = useState<V3UserDraft[]>(
    (values.snmp_v3_users || []).map(userToDraft),
  );

  // Dirty detection — driving the disabled state on the Save button.
  const dirty =
    enabled !== values.snmp_enabled ||
    version !== values.snmp_version ||
    community !== undefined ||
    sources !== (values.snmp_allowed_sources || []).join(", ") ||
    sysContact !== (values.snmp_sys_contact ?? "") ||
    sysLocation !== (values.snmp_sys_location ?? "") ||
    JSON.stringify(
      users.map((u) => ({ ...u, auth_pass: undefined, priv_pass: undefined })),
    ) !== JSON.stringify((values.snmp_v3_users || []).map(userToDraft)) ||
    users.some((u) => u.auth_pass !== undefined || u.priv_pass !== undefined);

  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const mutation = useMutation({
    mutationFn: (patch: Partial<PlatformSettings>) => settingsApi.update(patch),
    onSuccess: (updated) => {
      qc.setQueryData(["settings"], updated);
      setCommunity(undefined);
      setUsers((updated.snmp_v3_users || []).map(userToDraft));
      setSysContact(updated.snmp_sys_contact ?? "");
      setSysLocation(updated.snmp_sys_location ?? "");
      setSources((updated.snmp_allowed_sources || []).join(", "));
      setVersion(updated.snmp_version);
      setEnabled(updated.snmp_enabled);
      setSaveErr(null);
      setSavedAt(Date.now());
      setTimeout(() => setSavedAt(null), 2500);
    },
    // formatDialogError, not err.message: on an AxiosError the latter is only
    // "Request failed with status code N", which hides the server's reason,
    // the validator's sentence naming the refused value (#3424).
    onError: (err: unknown) => {
      setSaveErr(formatDialogError(err));
    },
  });

  function buildPatch(): Partial<PlatformSettings> {
    const patch: Partial<PlatformSettings> = {
      snmp_enabled: enabled,
      snmp_version: version,
      snmp_sys_contact: sysContact,
      snmp_sys_location: sysLocation,
      // Trim + drop empty entries; the backend validator canonicalises
      // each CIDR via ``ip_network`` so duplicates collapse there too.
      snmp_allowed_sources: sources
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    };
    if (community !== undefined) patch.snmp_community = community;
    // v3 users always send the full list — the backend uses it as the
    // atomic-replace shape with per-user pass merge keyed by username.
    patch.snmp_v3_users = users.map(
      draftToWrite,
    ) as unknown as PlatformSettings["snmp_v3_users"];
    return patch;
  }

  function handleSave() {
    mutation.mutate(buildPatch());
  }

  function addUser() {
    setUsers((prev) => [
      ...prev,
      {
        username: "",
        auth_protocol: "none",
        auth_pass_set: false,
        priv_protocol: "none",
        priv_pass_set: false,
      },
    ]);
  }

  function updateUser(idx: number, partial: Partial<V3UserDraft>) {
    setUsers((prev) =>
      prev.map((u, i) => (i === idx ? { ...u, ...partial } : u)),
    );
  }

  function removeUser(idx: number) {
    setUsers((prev) => prev.filter((_, i) => i !== idx));
  }

  return (
    <div className="space-y-2">
      {!applianceMode && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-400">
              snmpd is only configured on appliance hosts
            </p>
            <p className="text-muted-foreground">
              This control plane is running in docker / k8s, where snmpd isn't
              part of the SpatiumDDI image. Use the platform's Prometheus
              metrics endpoint for monitoring instead. Settings saved here still
              flow through the ConfigBundle to any <em>appliance agents</em>{" "}
              registered with this control plane — useful for hybrid
              deployments.
            </p>
          </div>
        </div>
      )}

      <Field
        label="Enable SNMP"
        description="When on, the rendered snmpd.conf is shipped to every appliance host through the ConfigBundle long-poll, the host runner checks it with a probe run of snmpd, and starts snmpd."
      >
        <Toggle
          checked={enabled}
          onChange={setEnabled}
          disabled={!isSuperadmin}
        />
      </Field>

      <Field
        label="Version"
        description="v2c — community-string auth; simplest setup, recommended for lab + small-shop monitoring. v3 — user-based auth + privacy; needed for compliance-driven SNMP."
      >
        <select
          value={version}
          onChange={(e) => setVersion(e.target.value as SnmpVersion)}
          disabled={!isSuperadmin}
          className={inputCls}
        >
          <option value="v2c">v2c (community)</option>
          <option value="v3">v3 (USM)</option>
        </select>
      </Field>

      {version === "v2c" && (
        <CommunityField
          values={values}
          draft={community}
          setDraft={setCommunity}
          isSuperadmin={isSuperadmin}
          inputCls={inputCls}
        />
      )}

      {version === "v3" && (
        <div className="rounded-md border bg-muted/30 p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-sm font-medium">v3 USM users</div>
              <div className="text-xs text-muted-foreground">
                Per-user authentication. Each user can independently set
                auth-only or auth+priv. Leaving a password field blank keeps the
                existing ciphertext; clearing turns the protocol off.
              </div>
            </div>
            <button
              type="button"
              onClick={addUser}
              disabled={!isSuperadmin}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
            >
              <Plus className="h-3 w-3" />
              Add user
            </button>
          </div>
          {users.length === 0 ? (
            <div className="py-2 text-xs text-muted-foreground">
              No v3 users configured.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="py-1 pr-2">Username</th>
                    <th className="py-1 pr-2">Auth</th>
                    <th className="py-1 pr-2">Auth pass</th>
                    <th className="py-1 pr-2">Priv</th>
                    <th className="py-1 pr-2">Priv pass</th>
                    <th className="py-1"></th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u, idx) => (
                    <tr key={idx} className="border-b last:border-b-0">
                      <td className="py-1 pr-2">
                        <input
                          type="text"
                          value={u.username}
                          onChange={(e) =>
                            updateUser(idx, { username: e.target.value })
                          }
                          disabled={!isSuperadmin}
                          className={cn(inputCls, "w-32")}
                        />
                      </td>
                      <td className="py-1 pr-2">
                        <select
                          value={u.auth_protocol}
                          onChange={(e) =>
                            updateUser(idx, {
                              auth_protocol: e.target.value as SnmpAuthProtocol,
                            })
                          }
                          disabled={!isSuperadmin}
                          className={inputCls}
                        >
                          <option value="none">none</option>
                          <option value="MD5">MD5</option>
                          <option value="SHA">SHA</option>
                        </select>
                      </td>
                      <td className="py-1 pr-2">
                        {u.auth_protocol === "none" ? (
                          <span className="text-muted-foreground">—</span>
                        ) : (
                          <PassInput
                            isSet={u.auth_pass_set}
                            value={u.auth_pass}
                            onChange={(v) => updateUser(idx, { auth_pass: v })}
                            disabled={!isSuperadmin}
                            inputCls={inputCls}
                          />
                        )}
                      </td>
                      <td className="py-1 pr-2">
                        <select
                          value={u.priv_protocol}
                          onChange={(e) =>
                            updateUser(idx, {
                              priv_protocol: e.target.value as SnmpPrivProtocol,
                            })
                          }
                          disabled={!isSuperadmin}
                          className={inputCls}
                        >
                          <option value="none">none</option>
                          <option value="DES">DES</option>
                          <option value="AES">AES</option>
                        </select>
                      </td>
                      <td className="py-1 pr-2">
                        {u.priv_protocol === "none" ? (
                          <span className="text-muted-foreground">—</span>
                        ) : (
                          <PassInput
                            isSet={u.priv_pass_set}
                            value={u.priv_pass}
                            onChange={(v) => updateUser(idx, { priv_pass: v })}
                            disabled={!isSuperadmin}
                            inputCls={inputCls}
                          />
                        )}
                      </td>
                      <td className="py-1">
                        <button
                          type="button"
                          onClick={() => removeUser(idx)}
                          disabled={!isSuperadmin}
                          className="rounded p-1 text-destructive hover:bg-destructive/10 disabled:opacity-40"
                          title="Remove user"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <Field
        label="Allowed source CIDRs"
        description="Comma- or space-separated list of CIDRs allowed to query SNMP. The host firewall opens UDP 161 only to these sources, for v2c and v3. Empty = the port is open to any source (v2c still answers nothing until a source is listed; v3 is then protected only by its user credentials). A custom firewall_extra rule accepting UDP 161 adds its sources to this list."
      >
        <input
          type="text"
          value={sources}
          onChange={(e) => setSources(e.target.value)}
          placeholder="10.0.0.0/8, 192.168.0.0/16"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-96 max-w-full font-mono")}
        />
      </Field>

      <Field
        label="sysContact"
        description="Operator contact string returned by SNMPv2-MIB::sysContact.0. Free-form (email + on-call rotation is the canonical shape)."
      >
        <input
          type="text"
          value={sysContact}
          onChange={(e) => setSysContact(e.target.value)}
          placeholder="ops@example.com"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-80 max-w-full")}
        />
      </Field>

      <Field
        label="sysLocation"
        description="Physical location returned by SNMPv2-MIB::sysLocation.0."
      >
        <input
          type="text"
          value={sysLocation}
          onChange={(e) => setSysLocation(e.target.value)}
          placeholder="Datacenter A, Rack 12"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-80 max-w-full")}
        />
      </Field>

      <div className="mt-4 flex items-center gap-3 border-t pt-4">
        <button
          type="button"
          onClick={handleSave}
          disabled={!isSuperadmin || !dirty || mutation.isPending}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
        >
          {mutation.isPending
            ? "Saving…"
            : savedAt
              ? "Saved!"
              : "Save SNMP settings"}
        </button>
        {saveErr && (
          <span className="text-xs text-destructive">
            Failed to save: {saveErr}
          </span>
        )}
      </div>
    </div>
  );
}

function PassInput({
  isSet,
  value,
  onChange,
  disabled,
  inputCls,
}: {
  isSet: boolean;
  value: string | undefined;
  onChange: (v: string | undefined) => void;
  disabled: boolean;
  inputCls: string;
}) {
  // ``value === undefined`` = leave existing alone. The UI shows a
  // "Configured ✓" chip + a [Replace…] button. Clicking sets value="" so
  // the operator can type a new pass. To clear without replacing, click
  // [Clear] (sends ``""`` on save — backend's _resolve_pass clears the
  // stored ciphertext).
  if (isSet && value === undefined) {
    return (
      <div className="flex items-center gap-1">
        <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">
          Set ✓
        </span>
        <button
          type="button"
          onClick={() => onChange("")}
          disabled={disabled}
          className="rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent disabled:opacity-40"
        >
          Replace…
        </button>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1">
      <input
        type="password"
        autoComplete="off"
        spellCheck={false}
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={isSet ? "(replace existing)" : "Enter password"}
        disabled={disabled}
        className={cn(inputCls, "w-32 font-mono text-xs")}
      />
      {isSet && (
        <button
          type="button"
          onClick={() => onChange(undefined)}
          disabled={disabled}
          className="rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent disabled:opacity-40"
          title="Cancel — keep existing"
        >
          Cancel
        </button>
      )}
    </div>
  );
}

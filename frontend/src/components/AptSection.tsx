// Appliance APT host-config form (issue #155). Mirrors SNMPSection /
// NTPSection: a self-contained form with its own atomic Save, driven by
// the shared ``settingsApi`` PUT /settings surface. Adds a Validate
// button (no other host-config plane needs one) because a bad apt
// config bricks ``apt update`` and there's no GUI to recover short of
// SSH — so the operator sees a structural pass/fail before Save.
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, AlertTriangle, Check, Plus, Trash2 } from "lucide-react";

import {
  formatApiError,
  settingsApi,
  type AptAuthUpdate,
  type AptGpgKeyUpdate,
  type AptSource,
  type AptValidateResponse,
  type PlatformSettings,
} from "@/lib/api";
import { Toggle } from "@/components/ui/toggle";
import { cn } from "@/lib/utils";

interface Props {
  values: PlatformSettings;
  isSuperadmin: boolean;
  applianceMode: boolean;
  inputCls: string;
}

// Local edit shapes carry the redacted ``*_set`` flag plus a fresh
// plaintext field the operator can type into (kept out of the wire
// unless non-empty — empty = preserve the stored ciphertext).
interface GpgKeyEdit {
  key_id: string;
  comment: string;
  armoured_text_set: boolean;
  armoured_text: string;
}
interface AuthEdit {
  machine: string;
  login: string;
  password_set: boolean;
  password: string;
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

export function AptSection({
  values,
  isSuperadmin,
  applianceMode,
  inputCls,
}: Props) {
  const qc = useQueryClient();
  const [managed, setManaged] = useState(values.apt_managed);
  const [sources, setSources] = useState<AptSource[]>(values.apt_sources || []);
  const [gpgKeys, setGpgKeys] = useState<GpgKeyEdit[]>(
    (values.apt_gpg_keys || []).map((k) => ({
      key_id: k.key_id,
      comment: k.comment,
      armoured_text_set: k.armoured_text_set,
      armoured_text: "",
    })),
  );
  const [proxyHttp, setProxyHttp] = useState(values.apt_proxy_http);
  const [proxyHttps, setProxyHttps] = useState(values.apt_proxy_https);
  const [noProxy, setNoProxy] = useState(values.apt_proxy_no_proxy);
  const [auth, setAuth] = useState<AuthEdit[]>(
    (values.apt_auth || []).map((a) => ({
      machine: a.machine,
      login: a.login,
      password_set: a.password_set,
      password: "",
    })),
  );
  const [unattended, setUnattended] = useState(
    values.apt_unattended_upgrades_enabled,
  );
  // Issue #164 — unattended-upgrades policy. Origins / blocklist are edited as
  // newline-separated textareas and split to arrays on save.
  const [uuOrigins, setUuOrigins] = useState(
    (values.apt_unattended_origins || []).join("\n"),
  );
  const [uuBlocklist, setUuBlocklist] = useState(
    (values.apt_unattended_blocklist || []).join("\n"),
  );
  const [uuAutoReboot, setUuAutoReboot] = useState(
    values.apt_unattended_automatic_reboot,
  );
  const [uuRebootTime, setUuRebootTime] = useState(
    values.apt_unattended_reboot_time || "02:00",
  );
  const [touched, setTouched] = useState(false);
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [validation, setValidation] = useState<AptValidateResponse | null>(
    null,
  );

  // Any edit invalidates a prior structural check — clear the stale banner
  // so the operator can't read a "passed" result that no longer applies.
  const mark = () => {
    setTouched(true);
    setValidation(null);
  };

  function buildGpgUpdate(): AptGpgKeyUpdate[] {
    return gpgKeys
      .filter((k) => k.key_id.trim())
      .map((k) => ({
        key_id: k.key_id.trim(),
        comment: k.comment,
        // Only send armoured_text when the operator typed one (replace /
        // add); omit otherwise so the backend preserves the stored key.
        ...(k.armoured_text.trim() ? { armoured_text: k.armoured_text } : {}),
      }));
  }
  function buildAuthUpdate(): AptAuthUpdate[] {
    return auth
      .filter((a) => a.machine.trim() && a.login.trim())
      .map((a) => ({
        machine: a.machine.trim(),
        login: a.login.trim(),
        ...(a.password.trim() ? { password: a.password } : {}),
      }));
  }

  const saveMut = useMutation({
    mutationFn: () =>
      settingsApi.updateApt({
        apt_managed: managed,
        apt_sources: sources,
        apt_gpg_keys: buildGpgUpdate(),
        apt_proxy_http: proxyHttp,
        apt_proxy_https: proxyHttps,
        apt_proxy_no_proxy: noProxy,
        apt_auth: buildAuthUpdate(),
        apt_unattended_upgrades_enabled: unattended,
        apt_unattended_origins: uuOrigins
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        apt_unattended_blocklist: uuBlocklist
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        apt_unattended_automatic_reboot: uuAutoReboot,
        apt_unattended_reboot_time: uuRebootTime.trim(),
      }),
    onSuccess: (updated) => {
      qc.setQueryData(["settings"], updated);
      setGpgKeys(
        (updated.apt_gpg_keys || []).map((k) => ({
          key_id: k.key_id,
          comment: k.comment,
          armoured_text_set: k.armoured_text_set,
          armoured_text: "",
        })),
      );
      setAuth(
        (updated.apt_auth || []).map((a) => ({
          machine: a.machine,
          login: a.login,
          password_set: a.password_set,
          password: "",
        })),
      );
      setSources(updated.apt_sources || []);
      // #164 — re-sync the unattended policy fields from the server response
      // so backend normalisation (dropped-empty origins, stripped whitespace)
      // is reflected instead of the operator's raw textarea input.
      setUuOrigins((updated.apt_unattended_origins || []).join("\n"));
      setUuBlocklist((updated.apt_unattended_blocklist || []).join("\n"));
      setUuAutoReboot(updated.apt_unattended_automatic_reboot);
      setUuRebootTime(updated.apt_unattended_reboot_time || "02:00");
      setSaveErr(null);
      setTouched(false);
      setSavedAt(Date.now());
      setTimeout(() => setSavedAt(null), 2500);
    },
    // formatApiError, not err.message: an AxiosError's message is only
    // "Request failed with status code 422", which hides the validator's
    // sentence naming the offending entry (#1384).
    onError: (err: unknown) => setSaveErr(formatApiError(err)),
  });

  const validateMut = useMutation({
    mutationFn: () =>
      settingsApi.validateApt({
        apt_sources: sources,
        apt_gpg_key_ids: gpgKeys.map((k) => k.key_id.trim()).filter(Boolean),
        apt_proxy_http: proxyHttp,
        apt_proxy_https: proxyHttps,
      }),
    onSuccess: (res) => setValidation(res),
  });

  const ro = !isSuperadmin;

  return (
    <div className="space-y-3">
      {!applianceMode && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-400">
              APT is only configured on appliance hosts
            </p>
            <p className="text-muted-foreground">
              This control plane runs in docker / k8s, where apt isn't part of
              the SpatiumDDI image. Settings saved here still flow through the
              ConfigBundle to any <em>appliance agents</em> registered with this
              control plane.
            </p>
          </div>
        </div>
      )}

      <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
        <p className="text-muted-foreground">
          A bad APT config blocks security updates and there's no GUI to recover
          from a broken <code>apt update</code> short of SSH. Click{" "}
          <strong>Validate</strong> before saving — the appliance host
          re-validates against a staged config before swapping the live files,
          but the structural pre-check here catches mistakes early.
        </p>
      </div>

      <Field
        label="Manage APT with SpatiumDDI"
        description="Off (default) — the appliance keeps Debian's baked sources.list, untouched. On — SpatiumDDI renders /etc/apt/sources.list.d/spatiumddi.list (+ proxy / auth / keyrings) from the config below and neutralises the baked sources.list. The original is backed up and restored if you turn this off."
      >
        <Toggle
          checked={managed}
          onChange={(v) => {
            setManaged(v);
            mark();
          }}
          disabled={ro}
        />
      </Field>

      {/* ── Sources ── */}
      <div className="border-t pt-3">
        <div className="mb-2 flex items-center justify-between">
          <div className="text-sm font-medium">Repositories</div>
          <button
            type="button"
            disabled={ro}
            onClick={() => {
              setSources((p) => [
                ...p,
                {
                  name: "",
                  uri: "",
                  suites: "",
                  components: "main",
                  signed_by_key_id: "",
                  enabled: true,
                },
              ]);
              mark();
            }}
            className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" /> Add repo
          </button>
        </div>
        <div className="space-y-2">
          {sources.length === 0 && (
            <p className="text-xs text-muted-foreground">
              No repositories configured.
            </p>
          )}
          {sources.map((s, i) => (
            <div
              key={i}
              className="grid grid-cols-1 gap-1.5 rounded-md border p-2 sm:grid-cols-2"
            >
              <input
                className={inputCls}
                placeholder="Name (label)"
                value={s.name}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setSources((p) =>
                    p.map((x, j) => (j === i ? { ...x, name: v } : x)),
                  );
                  mark();
                }}
              />
              <input
                className={inputCls}
                placeholder="URI (http://deb.debian.org/debian)"
                value={s.uri}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setSources((p) =>
                    p.map((x, j) => (j === i ? { ...x, uri: v } : x)),
                  );
                  mark();
                }}
              />
              <input
                className={inputCls}
                placeholder="Suites (trixie trixie-updates)"
                value={s.suites}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setSources((p) =>
                    p.map((x, j) => (j === i ? { ...x, suites: v } : x)),
                  );
                  mark();
                }}
              />
              <input
                className={inputCls}
                placeholder="Components (main contrib)"
                value={s.components}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setSources((p) =>
                    p.map((x, j) => (j === i ? { ...x, components: v } : x)),
                  );
                  mark();
                }}
              />
              <select
                className={inputCls}
                value={s.signed_by_key_id}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setSources((p) =>
                    p.map((x, j) =>
                      j === i ? { ...x, signed_by_key_id: v } : x,
                    ),
                  );
                  mark();
                }}
              >
                <option value="">— signing key (none) —</option>
                {gpgKeys
                  .filter((k) => k.key_id.trim())
                  .map((k) => (
                    <option key={k.key_id} value={k.key_id}>
                      {k.key_id}
                      {k.comment ? ` (${k.comment})` : ""}
                    </option>
                  ))}
              </select>
              <div className="flex items-center justify-between gap-2">
                <label className="flex items-center gap-1.5 text-xs">
                  <input
                    type="checkbox"
                    checked={s.enabled}
                    disabled={ro}
                    onChange={(e) => {
                      const v = e.target.checked;
                      setSources((p) =>
                        p.map((x, j) => (j === i ? { ...x, enabled: v } : x)),
                      );
                      mark();
                    }}
                  />
                  Enabled
                </label>
                <button
                  type="button"
                  disabled={ro}
                  onClick={() => {
                    setSources((p) => p.filter((_, j) => j !== i));
                    mark();
                  }}
                  className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-50"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── GPG keys ── */}
      <div className="border-t pt-3">
        <div className="mb-2 flex items-center justify-between">
          <div className="text-sm font-medium">GPG signing keys</div>
          <button
            type="button"
            disabled={ro}
            onClick={() => {
              setGpgKeys((p) => [
                ...p,
                {
                  key_id: "",
                  comment: "",
                  armoured_text_set: false,
                  armoured_text: "",
                },
              ]);
              mark();
            }}
            className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" /> Add key
          </button>
        </div>
        <div className="space-y-2">
          {gpgKeys.map((k, i) => (
            <div key={i} className="space-y-1.5 rounded-md border p-2">
              <div className="flex gap-1.5">
                <input
                  className={cn(inputCls, "flex-1")}
                  placeholder="Key id (filename-safe, e.g. debian-archive)"
                  value={k.key_id}
                  disabled={ro}
                  onChange={(e) => {
                    const v = e.target.value;
                    setGpgKeys((p) =>
                      p.map((x, j) => (j === i ? { ...x, key_id: v } : x)),
                    );
                    mark();
                  }}
                />
                <input
                  className={cn(inputCls, "flex-1")}
                  placeholder="Comment"
                  value={k.comment}
                  disabled={ro}
                  onChange={(e) => {
                    const v = e.target.value;
                    setGpgKeys((p) =>
                      p.map((x, j) => (j === i ? { ...x, comment: v } : x)),
                    );
                    mark();
                  }}
                />
                <button
                  type="button"
                  disabled={ro}
                  onClick={() => {
                    setGpgKeys((p) => p.filter((_, j) => j !== i));
                    mark();
                  }}
                  className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-50"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
              <textarea
                className={cn(inputCls, "w-full font-mono text-xs")}
                rows={3}
                placeholder={
                  k.armoured_text_set
                    ? "Armoured key stored — paste a new one to replace"
                    : "-----BEGIN PGP PUBLIC KEY BLOCK----- …"
                }
                value={k.armoured_text}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setGpgKeys((p) =>
                    p.map((x, j) => (j === i ? { ...x, armoured_text: v } : x)),
                  );
                  mark();
                }}
              />
            </div>
          ))}
        </div>
      </div>

      {/* ── Proxy ── */}
      <div className="space-y-1 border-t pt-3">
        <div className="text-sm font-medium">Proxy</div>
        <input
          className={cn(inputCls, "w-full")}
          placeholder="HTTP proxy (http://proxy.internal:3128/)"
          value={proxyHttp}
          disabled={ro}
          onChange={(e) => {
            setProxyHttp(e.target.value);
            mark();
          }}
        />
        <input
          className={cn(inputCls, "w-full")}
          placeholder="HTTPS proxy (optional)"
          value={proxyHttps}
          disabled={ro}
          onChange={(e) => {
            setProxyHttps(e.target.value);
            mark();
          }}
        />
        <input
          className={cn(inputCls, "w-full")}
          placeholder="no_proxy (comma-separated hosts)"
          value={noProxy}
          disabled={ro}
          onChange={(e) => {
            setNoProxy(e.target.value);
            mark();
          }}
        />
      </div>

      {/* ── Private-mirror auth ── */}
      <div className="border-t pt-3">
        <div className="mb-2 flex items-center justify-between">
          <div className="text-sm font-medium">Private-mirror credentials</div>
          <button
            type="button"
            disabled={ro}
            onClick={() => {
              setAuth((p) => [
                ...p,
                { machine: "", login: "", password_set: false, password: "" },
              ]);
              mark();
            }}
            className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" /> Add credential
          </button>
        </div>
        <div className="space-y-1.5">
          {auth.map((a, i) => (
            <div key={i} className="flex gap-1.5">
              <input
                className={cn(inputCls, "flex-1")}
                placeholder="machine (host)"
                value={a.machine}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setAuth((p) =>
                    p.map((x, j) => (j === i ? { ...x, machine: v } : x)),
                  );
                  mark();
                }}
              />
              <input
                className={cn(inputCls, "flex-1")}
                placeholder="login"
                value={a.login}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setAuth((p) =>
                    p.map((x, j) => (j === i ? { ...x, login: v } : x)),
                  );
                  mark();
                }}
              />
              <input
                className={cn(inputCls, "flex-1")}
                type="password"
                placeholder={a.password_set ? "•••• (stored)" : "password"}
                value={a.password}
                disabled={ro}
                onChange={(e) => {
                  const v = e.target.value;
                  setAuth((p) =>
                    p.map((x, j) => (j === i ? { ...x, password: v } : x)),
                  );
                  mark();
                }}
              />
              <button
                type="button"
                disabled={ro}
                onClick={() => {
                  setAuth((p) => p.filter((_, j) => j !== i));
                  mark();
                }}
                className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-50"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      <Field
        label="Unattended security upgrades"
        description="When on, the appliance's daily unattended-upgrades run installs security patches automatically. Turn off for air-gapped sites until you've pointed at a reachable mirror."
      >
        <Toggle
          checked={unattended}
          onChange={(v) => {
            setUnattended(v);
            mark();
          }}
          disabled={ro}
        />
      </Field>

      {/* ── Unattended-upgrades policy (issue #164) ── */}
      <div className="space-y-2 border-t pt-3">
        <div className="text-sm font-medium">Unattended-upgrades policy</div>
        <div className="text-xs text-muted-foreground">
          Controls what the daily unattended run installs and whether it
          reboots. Applies even without managed APT sources. An empty
          allowed-origins list means nothing is auto-upgraded.
        </div>
        <label className="block text-xs font-medium">
          Allowed origins (one per line)
        </label>
        <textarea
          className={cn(inputCls, "w-full font-mono text-xs")}
          rows={3}
          placeholder={"${distro_id}:${distro_codename}-security"}
          value={uuOrigins}
          disabled={ro}
          onChange={(e) => {
            setUuOrigins(e.target.value);
            mark();
          }}
        />
        <label className="block text-xs font-medium">
          Package blocklist — never auto-upgraded. One regular expression per
          line, matched from the start of the package name (not a glob:{" "}
          <code>linux-image-</code>, <code>^openssl$</code>)
        </label>
        <textarea
          className={cn(inputCls, "w-full font-mono text-xs")}
          rows={2}
          placeholder={"linux-image-\n^openssl$"}
          value={uuBlocklist}
          disabled={ro}
          onChange={(e) => {
            setUuBlocklist(e.target.value);
            mark();
          }}
        />
      </div>

      <Field
        label="Automatic reboot after upgrades"
        description="Reboot automatically when an installed update requires it. Off by default — a surprise reboot is risky for a DDI appliance serving DNS / DHCP."
      >
        <Toggle
          checked={uuAutoReboot}
          onChange={(v) => {
            setUuAutoReboot(v);
            mark();
          }}
          disabled={ro}
        />
      </Field>

      <Field
        label="Reboot time"
        description="HH:MM (24-hour) for the automatic reboot, when enabled."
      >
        <input
          className={cn(inputCls, "w-28")}
          placeholder="02:00"
          value={uuRebootTime}
          disabled={ro || !uuAutoReboot}
          onChange={(e) => {
            setUuRebootTime(e.target.value);
            mark();
          }}
        />
      </Field>

      {/* ── Validation result ── */}
      {validation && (
        <div
          className={cn(
            "space-y-1 rounded-md border p-3 text-xs",
            validation.valid
              ? "border-emerald-500/40 bg-emerald-500/10"
              : "border-destructive/40 bg-destructive/10",
          )}
        >
          <p className="font-medium">
            {validation.valid
              ? "Structural check passed."
              : "Structural check failed."}
          </p>
          {validation.errors.map((e, i) => (
            <p key={`e${i}`} className="text-destructive">
              • {e}
            </p>
          ))}
          {validation.warnings.map((w, i) => (
            <p key={`w${i}`} className="text-amber-700 dark:text-amber-400">
              ⚠ {w}
            </p>
          ))}
        </div>
      )}

      {/* ── Actions ── */}
      <div className="flex items-center gap-2 border-t pt-3">
        <button
          type="button"
          disabled={ro || validateMut.isPending}
          onClick={() => validateMut.mutate()}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
        >
          {validateMut.isPending ? "Validating…" : "Validate"}
        </button>
        <button
          type="button"
          disabled={ro || !touched || saveMut.isPending}
          onClick={() => saveMut.mutate()}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {saveMut.isPending ? "Saving…" : "Save"}
        </button>
        {savedAt && (
          <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
            <Check className="h-3.5 w-3.5" /> Saved
          </span>
        )}
        {saveErr && <span className="text-xs text-destructive">{saveErr}</span>}
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";

import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import {
  formatApiError,
  webExposureApi,
  type WebExposureConfig,
  type WebExposureConfigResponse,
} from "@/lib/api";
import { WebExposureEvidence } from "@/components/WebExposureCard";

/**
 * Settings → Security → Reachability (#3651).
 *
 * Detection is the `security.web_exposure` feature module (off by default,
 * Features & Integrations). This section holds the trusted-networks list, the
 * "intentional" acknowledgement, the evaluation window, the evidence table
 * with a one-click "this is ours", and the opt-in mitigations. Every
 * mitigation is off by default, and the copy next to each one says why the
 * operator cannot be locked out of their own control plane by it.
 */

const inputCls =
  "rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60";

function Check({
  label,
  hint,
  checked,
  onChange,
  disabled,
  title,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <label
      className="flex items-start gap-3 py-2 text-sm"
      title={disabled ? title : undefined}
    >
      <input
        type="checkbox"
        className="mt-1"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span className="font-medium">{label}</span>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </label>
  );
}

function Num({
  label,
  value,
  onChange,
  disabled,
  unit,
  min = 1,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  disabled?: boolean;
  unit: string;
  min?: number;
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-muted-foreground">
      <span className="w-52">{label}</span>
      <input
        type="number"
        min={min}
        value={value}
        disabled={disabled}
        aria-label={label}
        onChange={(e) => onChange(Number(e.target.value))}
        className={`${inputCls} w-24`}
      />
      <span>{unit}</span>
    </label>
  );
}

export function WebExposureSection() {
  const qc = useQueryClient();
  const { isSuperadmin } = usePermissions();
  const gate = permissionGate(isSuperadmin, NEEDS_SUPERADMIN);
  const { data, error } = useQuery({
    queryKey: ["web-exposure", "config"],
    queryFn: webExposureApi.getConfig,
    enabled: isSuperadmin,
    retry: false,
  });
  const [form, setForm] = useState<WebExposureConfig | null>(null);
  const [networks, setNetworks] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    if (data && !form) {
      setForm(data.config);
      setNetworks(data.config.trusted_networks.join("\n"));
    }
  }, [data, form]);

  const apply = (resp: WebExposureConfigResponse) => {
    qc.setQueryData(["web-exposure", "config"], resp);
    qc.invalidateQueries({ queryKey: ["web-exposure", "verdict"] });
    setForm(resp.config);
    setNetworks(resp.config.trusted_networks.join("\n"));
  };

  const save = useMutation({
    mutationFn: (body: WebExposureConfig) => webExposureApi.putConfig(body),
    onSuccess: (resp) => {
      apply(resp);
      setFailure(null);
      setNotice(
        resp.warnings?.length ? resp.warnings.join(" ") : "Settings saved.",
      );
    },
    onError: (e) => {
      setNotice(null);
      setFailure(formatApiError(e));
    },
  });
  const clearBans = useMutation({
    mutationFn: (bucket?: string) => webExposureApi.clearBans(bucket),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["web-exposure"] }),
    onError: (e) => setFailure(formatApiError(e)),
  });
  const trust = useMutation({
    mutationFn: (cidr: string) => webExposureApi.trustNetwork(cidr),
    onSuccess: apply,
    onError: (e) => setFailure(formatApiError(e)),
  });
  const allowList = useMutation({
    mutationFn: () => webExposureApi.applyWebUiAllowList({}),
    onSuccess: (r) => {
      setFailure(null);
      setNotice(
        `Web UI source restriction set to ${r.allowed_cidrs.length} networks.`,
      );
    },
    onError: (e) => {
      setNotice(null);
      setFailure(formatApiError(e));
    },
  });

  if (!isSuperadmin) {
    return (
      <p className="text-sm text-muted-foreground">
        Reachability settings are superadmin-only.
      </p>
    );
  }
  const moduleOff =
    (error as { response?: { status?: number } } | null)?.response?.status ===
    404;
  if (moduleOff) {
    return (
      <section className="space-y-2">
        <h2 className="flex items-center gap-2 text-base font-semibold">
          <ShieldAlert className="h-4 w-4" /> Reachability
        </h2>
        <p className="text-sm text-muted-foreground">
          Web exposure detection is off. Turn on{" "}
          <strong>Web exposure detection</strong> on the Features & Integrations
          page to start watching for requests from outside your networks. It
          makes no outbound connection and arms no mitigation on its own.
        </p>
      </section>
    );
  }
  if (!data || !form) return null;

  const set = <K extends keyof WebExposureConfig>(
    k: K,
    v: WebExposureConfig[K],
  ) => setForm({ ...form, [k]: v });
  const parsed = networks
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const body: WebExposureConfig = { ...form, trusted_networks: parsed };
  const insideNow =
    data.caller_class === "internal" || data.caller_class === "trusted";

  return (
    <section className="space-y-6">
      <div>
        <h2 className="flex items-center gap-2 text-base font-semibold">
          <ShieldAlert className="h-4 w-4" /> Reachability
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Is this install reachable from outside your networks? Entirely local:
          nothing here makes an outbound connection. “Internal” means private
          address space (RFC 1918, CGNAT 100.64/10, ULA fc00::/7, loopback,
          link-local) plus the trusted networks below. You are connecting from{" "}
          <span className="font-mono">{data.caller_ip ?? "unknown"}</span> (
          {data.caller_class ?? "unknown"}).
        </p>
      </div>

      <WebExposureEvidence
        showTrust
        onTrust={(cidr) => trust.mutate(cidr)}
        trusting={trust.isPending}
      />

      <div className="space-y-2">
        <h3 className="text-sm font-semibold">Trusted networks</h3>
        <p className="text-xs text-muted-foreground">
          Only needed for public ranges you use internally (a university or ISP
          numbered from its own allocation, a VPN that hands out public
          addresses). Empty by default. This is a classification list, not an
          allow-list: nothing is refused because of it, and everything in it
          (plus private space) is exempt from every mitigation below.
        </p>
        <textarea
          aria-label="Trusted networks"
          rows={3}
          value={networks}
          disabled={!isSuperadmin}
          onChange={(e) => setNetworks(e.target.value)}
          placeholder="203.0.113.0/24"
          className={`${inputCls} w-full font-mono`}
        />
        <Check
          label="This install is intentionally reachable from the internet"
          hint="Demotes the reachability alert to info. Attack evidence (failed sign-ins, username spray) still escalates to critical."
          checked={form.intentional}
          onChange={(v) => set("intentional", v)}
        />
        <div className="flex flex-wrap gap-6">
          <Num
            label="Evaluation window"
            unit="hours"
            value={form.window_hours}
            onChange={(v) => set("window_hours", v)}
          />
          <Num
            label="Exposed at"
            unit="outside networks"
            value={form.threshold}
            onChange={(v) => set("threshold", v)}
          />
        </div>
      </div>

      <div className="space-y-2 rounded-lg border p-4">
        <h3 className="text-sm font-semibold">
          Mitigations (all off by default)
        </h3>
        <p className="text-xs text-muted-foreground">
          Nothing turns on because of a verdict. Every response below applies to{" "}
          <strong>external sources only</strong>: a source on a private network
          or in your trusted list is never throttled, banned or refused, so a
          wrong threshold cannot touch your own networks. Redis trouble fails
          open. Break glass if you cannot reach this page: set{" "}
          <code>WEB_EXPOSURE_MITIGATIONS=off</code> in the api environment and
          restart it (docs/features/SYSTEM_ADMIN.md).
          {data.break_glass_active && (
            <strong className="mt-1 block text-amber-600 dark:text-amber-400">
              Break glass is active: every mitigation is disabled whatever is
              set here.
            </strong>
          )}
        </p>

        <Check
          label="Tier 1a: stricter sign-in throttle for external sources"
          hint="A second per-network budget on sign-in for outside networks only, on top of the existing one. You will not be locked out: internal and trusted sources are exempt, a remote admin who trips it waits out the window, and it fails open."
          checked={form.external_throttle_enabled}
          onChange={(v) => set("external_throttle_enabled", v)}
        />
        {form.external_throttle_enabled && (
          <div className="ml-7 flex flex-wrap gap-6">
            <Num
              label="Attempts"
              unit="per network"
              value={form.external_throttle_attempts}
              onChange={(v) => set("external_throttle_attempts", v)}
            />
            <Num
              label="Window"
              unit="seconds"
              value={form.external_throttle_window_seconds}
              min={10}
              onChange={(v) => set("external_throttle_window_seconds", v)}
            />
          </div>
        )}

        <Check
          label="Tier 1b: temporary ban for a network that keeps failing sign-in"
          hint="After repeated failures from one outside network, refuse sign-in from it for a while, doubling up to a cap. You will not be locked out: internal and trusted sources are never banned, a ban expires by itself, and you can clear any ban below from an internal address. A restart of Redis clears the list. A remote admin sharing a network with an attacker is banned too, which is the trade."
          checked={form.ban_enabled}
          onChange={(v) => set("ban_enabled", v)}
        />
        {form.ban_enabled && (
          <div className="ml-7 flex flex-wrap gap-6">
            <Num
              label="Failures before a ban"
              unit="failures"
              min={3}
              value={form.ban_failures}
              onChange={(v) => set("ban_failures", v)}
            />
            <Num
              label="Counted within"
              unit="minutes"
              value={form.ban_failure_window_minutes}
              onChange={(v) => set("ban_failure_window_minutes", v)}
            />
            <Num
              label="First ban"
              unit="minutes"
              value={form.ban_base_minutes}
              onChange={(v) => set("ban_base_minutes", v)}
            />
            <Num
              label="Longest ban"
              unit="hours"
              value={form.ban_max_hours}
              onChange={(v) => set("ban_max_hours", v)}
            />
          </div>
        )}
        {data.bans && data.bans.length > 0 && (
          <div className="ml-7 rounded border p-2 text-xs">
            <div className="mb-1 font-medium">Active bans</div>
            {data.bans.map((b) => (
              <div
                key={b.bucket}
                className="flex items-center justify-between gap-2 py-0.5"
              >
                <span className="font-mono">{b.bucket}</span>
                <span className="text-muted-foreground">
                  level {b.level}, until{" "}
                  {new Date(b.until * 1000).toLocaleString()}
                </span>
                <button
                  type="button"
                  className="text-primary hover:underline"
                  onClick={() => clearBans.mutate(b.bucket)}
                >
                  Clear
                </button>
              </div>
            ))}
            <button
              type="button"
              className="mt-1 text-primary hover:underline"
              onClick={() => clearBans.mutate(undefined)}
            >
              Clear all
            </button>
          </div>
        )}
        {!data.bans_available && (
          <p className="ml-7 text-xs text-muted-foreground">
            The ban list could not be read (Redis unreachable).
          </p>
        )}

        <Check
          label="Tier 2: require a second factor from outside"
          hint={
            "A local account with no TOTP enrolled is refused at sign-in from an outside network, with a message to enrol from inside. TOTP-enrolled users, SSO / LDAP users and API tokens are unaffected. You will not be locked out because enabling it is refused unless you are connecting from an internal network or your own account has TOTP." +
            (data.superadmins_without_totp.length
              ? ` Local superadmins without TOTP who would be stranded from outside: ${data.superadmins_without_totp.join(", ")}.`
              : "")
          }
          checked={form.require_mfa_external}
          onChange={(v) => set("require_mfa_external", v)}
        />
        {!insideNow && (
          <p className="ml-7 text-xs text-amber-600 dark:text-amber-400">
            You are connecting from an outside address. Turning tier 2 on is
            refused unless your own account has TOTP.
          </p>
        )}

        <div className="flex items-center gap-3 pt-2">
          <button
            type="button"
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-60"
            disabled={save.isPending || !!gate.disabled}
            onClick={() => save.mutate(body)}
          >
            {save.isPending ? "Saving…" : "Save"}
          </button>
          {notice && <span className="text-xs text-emerald-600">{notice}</span>}
          {failure && (
            <span role="alert" className="text-xs text-destructive">
              {failure}
            </span>
          )}
        </div>
      </div>

      {data.appliance && (
        <div className="space-y-2 rounded-lg border p-4">
          <h3 className="text-sm font-semibold">
            Tier 3a: restrict the Web UI to your networks (appliance)
          </h3>
          <p className="text-xs text-muted-foreground">
            Writes the trusted networks plus private space ({" "}
            {data.private_ranges.join(", ")}) into the Web UI source
            restriction, which scopes ports 80 / 443 and the load balancer. It
            is the existing control with its existing lock-out guard: it is
            refused unless your own address stays covered, and the console is
            the recovery path.
          </p>
          <button
            type="button"
            className="rounded-md border px-3 py-1.5 text-sm disabled:opacity-60"
            disabled={allowList.isPending}
            onClick={() => allowList.mutate()}
          >
            Use trusted networks as the Web UI restriction
          </button>
        </div>
      )}
    </section>
  );
}

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Copy,
  Eye,
  EyeOff,
  Plus,
  Power,
  PowerOff,
  QrCode as QrCodeIcon,
  Trash2,
} from "lucide-react";
import {
  apiTokensApi,
  API_TOKEN_SCOPES,
  dnsApi,
  ipamApi,
  type ApiToken,
  type ApiTokenCreated,
  type ApiTokenResourceGrant,
  type ApiTokenScope,
} from "@/lib/api";
import { ReauthFields } from "@/components/ReauthFields";
import { copyToClipboard } from "@/lib/clipboard";
import {
  buildEnrolmentUri,
  connectionFromLocation,
  displayFingerprint,
  normaliseFingerprint,
  type EnrolmentConnection,
} from "@/lib/enrolment";
import { QrCode } from "@/components/QrCode";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/80">{hint}</p>}
    </div>
  );
}

// ── Create Token Modal ─────────────────────────────────────────────────────

function CreateTokenModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (token: ApiTokenCreated) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  // Sensible default: 90-day TTL. "Never" is an explicit choice since
  // long-lived bearers are a real security footgun — the UI makes it
  // slightly annoying on purpose.
  const [expiryMode, setExpiryMode] = useState<"days" | "never">("days");
  const [days, setDays] = useState<number>(90);
  const [scopes, setScopes] = useState<ApiTokenScope[]>([]);
  // Optional per-token resource binding (#374): bind to one subnet or DNS zone.
  const [bindType, setBindType] = useState<"none" | "subnet" | "dns_zone">(
    "none",
  );
  const [bindAction, setBindAction] = useState<"read" | "write" | "admin">(
    "write",
  );
  const [bindGroupId, setBindGroupId] = useState("");
  const [bindResourceId, setBindResourceId] = useState("");
  const [stepPassword, setStepPassword] = useState("");
  const [stepTotp, setStepTotp] = useState("");
  const [error, setError] = useState<string | null>(null);

  const subnetsQ = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
    enabled: bindType === "subnet",
  });
  const dnsGroupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: dnsApi.listGroups,
    enabled: bindType === "dns_zone",
  });
  const zonesQ = useQuery({
    queryKey: ["dns-zones", bindGroupId],
    queryFn: () => dnsApi.listZones(bindGroupId),
    enabled: bindType === "dns_zone" && !!bindGroupId,
  });

  const resourceGrants: ApiTokenResourceGrant[] =
    bindType !== "none" && bindResourceId
      ? [
          {
            action: bindAction,
            resource_type: bindType,
            resource_id: bindResourceId,
          },
        ]
      : [];

  const mut = useMutation({
    mutationFn: () =>
      apiTokensApi.create({
        name,
        description,
        expires_in_days: expiryMode === "never" ? null : days,
        scopes,
        resource_grants: resourceGrants,
        // #1355 — a token outlives the session, so minting one needs a
        // step-up from its owner.
        stepup_password: stepPassword || null,
        stepup_totp_code: stepTotp || null,
      }),
    onSuccess: (token) => {
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
      onCreated(token);
    },
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: unknown } } })
        ?.response?.data?.detail;
      setError(
        typeof detail === "string"
          ? detail
          : detail
            ? JSON.stringify(detail)
            : "Failed to create token.",
      );
    },
  });

  return (
    <Modal title="New API Token" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          mut.mutate();
        }}
        className="space-y-3"
      >
        <Field
          label="Name"
          hint="Shown in the list — pick something you'll recognise later (e.g. ‘terraform-ci’)."
        >
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. ansible-automation"
            required
            autoFocus
          />
        </Field>
        <Field label="Description (optional)">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What's this token used for?"
          />
        </Field>
        <Field
          label="Expires"
          hint="Long-lived tokens are a security risk — prefer a date unless you have a reason."
        >
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5 text-sm">
              <input
                type="radio"
                checked={expiryMode === "days"}
                onChange={() => setExpiryMode("days")}
              />
              <span>In</span>
              <input
                type="number"
                min={1}
                max={3650}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                disabled={expiryMode !== "days"}
                className={cn(inputCls, "w-20")}
              />
              <span>days</span>
            </label>
            <label className="flex items-center gap-1.5 text-sm">
              <input
                type="radio"
                checked={expiryMode === "never"}
                onChange={() => setExpiryMode("never")}
              />
              Never
            </label>
          </div>
        </Field>
        <Field
          label="Scopes (optional)"
          hint="Leave empty to inherit the owner's full RBAC. Pick one or more to restrict — multiple scopes union (any match passes)."
        >
          <div className="space-y-1.5">
            {API_TOKEN_SCOPES.map((s) => (
              <label
                key={s.value}
                className="flex items-start gap-2 text-xs cursor-pointer select-none"
              >
                <input
                  type="checkbox"
                  className="mt-0.5 h-3.5 w-3.5"
                  checked={scopes.includes(s.value)}
                  onChange={(e) => {
                    setScopes((prev) =>
                      e.target.checked
                        ? [...prev, s.value]
                        : prev.filter((x) => x !== s.value),
                    );
                  }}
                />
                <span>
                  <span className="font-medium">{s.label}</span>
                  <span className="text-muted-foreground"> — {s.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </Field>
        <Field
          label="Bind to a resource (optional)"
          hint="Restrict this token to a single subnet or DNS zone — a leaked CI secret can't touch anything else. The binding can never exceed your own permissions."
        >
          <div className="space-y-1.5">
            <select
              className={inputCls}
              value={bindType}
              onChange={(e) => {
                setBindType(e.target.value as "none" | "subnet" | "dns_zone");
                setBindResourceId("");
                setBindGroupId("");
              }}
            >
              <option value="none">No resource binding</option>
              <option value="subnet">Subnet</option>
              <option value="dns_zone">DNS zone</option>
            </select>
            {bindType !== "none" && (
              <select
                className={inputCls}
                value={bindAction}
                onChange={(e) =>
                  setBindAction(e.target.value as "read" | "write" | "admin")
                }
              >
                <option value="read">read</option>
                <option value="write">write</option>
                <option value="admin">admin</option>
              </select>
            )}
            {bindType === "subnet" && (
              <select
                className={inputCls}
                value={bindResourceId}
                onChange={(e) => setBindResourceId(e.target.value)}
              >
                <option value="">Select a subnet…</option>
                {(subnetsQ.data ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.network}
                    {s.name ? ` — ${s.name}` : ""}
                  </option>
                ))}
              </select>
            )}
            {bindType === "dns_zone" && (
              <>
                <select
                  className={inputCls}
                  value={bindGroupId}
                  onChange={(e) => {
                    setBindGroupId(e.target.value);
                    setBindResourceId("");
                  }}
                >
                  <option value="">Select a DNS group…</option>
                  {(dnsGroupsQ.data ?? []).map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
                {bindGroupId && (
                  <select
                    className={inputCls}
                    value={bindResourceId}
                    onChange={(e) => setBindResourceId(e.target.value)}
                  >
                    <option value="">Select a zone…</option>
                    {(zonesQ.data ?? []).map((z) => (
                      <option key={z.id} value={z.id}>
                        {z.name}
                      </option>
                    ))}
                  </select>
                )}
              </>
            )}
          </div>
        </Field>
        <div className="rounded-md border bg-muted/20 p-3">
          <p className="mb-2 text-xs text-muted-foreground">
            A token outlives this session, so creating one needs you to confirm
            who you are.
          </p>
          <ReauthFields
            password={stepPassword}
            onPassword={setStepPassword}
            totp={stepTotp}
            onTotp={setStepTotp}
          />
        </div>
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!name || mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Reveal-once Modal ──────────────────────────────────────────────────────
// ── Device enrolment QR (issue #906) ───────────────────────────────────────
//
// Typing or pasting a token across devices is the worst step in the mobile
// sign-in flow, and it is worse than annoying: an operator who cannot paste
// cleanly emails the token to themselves or reads it aloud, and the
// credential ends up somewhere it should never have been.
//
// Two payload shapes, per #906:
//
//   Token only    the bare token string — needs no format, works today
//   Server+token  spatiumddi://enrol?host=…&token=…&fingerprint=…
//
// The enrolment form is the interesting one because of the fingerprint. A
// self-hosted control plane usually presents a private-CA or self-signed
// certificate, so the client must ask the operator to confirm it — and
// comparing 64 hex characters by eye on a phone is exactly the check people
// skim. Carrying the fingerprint in a code scanned from inside an
// authenticated session turns that into a machine-checked comparison.
//
// The whole block is hidden behind an explicit reveal, matching the token
// text above it. That is not decoration: a QR makes the credential
// CAMERA-readable, so it is strictly easier to capture over a shoulder — or
// from a screen-share — than the masked string beside it.

function EnrolmentQr({ token }: { token: ApiTokenCreated }) {
  const [shown, setShown] = useState(false);
  const [mode, setMode] = useState<"enrol" | "token">("enrol");
  const [conn, setConn] = useState<EnrolmentConnection>(() =>
    connectionFromLocation(window.location),
  );
  const [pinCert, setPinCert] = useState(true);

  // Only fetched once the operator opens the section — no reason to ask the
  // server about certificates for an operator who just wants to copy-paste.
  const {
    data: ctx,
    isLoading: ctxLoading,
    isError: ctxError,
  } = useQuery({
    queryKey: ["api-token-enrolment-context"],
    queryFn: apiTokensApi.enrolmentContext,
    enabled: shown,
    staleTime: 5 * 60 * 1000,
  });

  // ONE predicate for "there is a fingerprint we can pin", used by both the
  // checkbox and the URI. Deriving them separately let the UI assert pinning
  // was on — naming a fingerprint in the copy — while `buildEnrolmentUri`
  // silently dropped a value `normaliseFingerprint` rejected.
  const pinnable = normaliseFingerprint(ctx?.tls_fingerprint_sha256);
  const fingerprint = pinCert ? pinnable : null;

  let payload: string | null = null;
  let buildError: string | null = null;
  if (mode === "token") {
    payload = token.token;
  } else if (ctxLoading) {
    // Hold the code back until we know whether it can carry a fingerprint.
    // Rendering it first would paint a complete, scannable, silently UNPINNED
    // enrolment code — and pinning is the whole point of this shape.
    buildError = "Checking this server's certificate…";
  } else {
    try {
      payload = buildEnrolmentUri({ ...conn, token: token.token, fingerprint });
    } catch (err) {
      // An empty host or a port that isn't a number — both are visible in the
      // fields right below, so surface what the builder actually objected to.
      buildError =
        err instanceof Error && err.message
          ? err.message
          : "Enter the address this server is reachable at.";
    }
  }

  if (!shown) {
    return (
      <button
        type="button"
        onClick={() => setShown(true)}
        className="flex w-full items-center justify-center gap-2 rounded-md border border-dashed px-3 py-2 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground"
      >
        <QrCodeIcon className="h-3.5 w-3.5" />
        Show enrolment QR code for the mobile app
      </button>
    );
  }

  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="inline-flex rounded-md border p-0.5 text-xs">
          <button
            type="button"
            onClick={() => setMode("enrol")}
            className={cn(
              "rounded px-2 py-1",
              mode === "enrol"
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            Server + token
          </button>
          <button
            type="button"
            onClick={() => setMode("token")}
            className={cn(
              "rounded px-2 py-1",
              mode === "token"
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            Token only
          </button>
        </div>
        <button
          type="button"
          onClick={() => setShown(false)}
          className="inline-flex items-center gap-1 rounded p-1 text-xs text-muted-foreground hover:bg-background hover:text-foreground"
          title="Hide the QR code"
        >
          <EyeOff className="h-3.5 w-3.5" />
          Hide
        </button>
      </div>

      <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-700 dark:text-amber-300">
        This code contains the token. Anything with a camera pointed at this
        screen can read it — don&apos;t show it on a shared screen or a call.
      </div>

      <div className="flex justify-center">
        {payload ? (
          <QrCode value={payload} size={216} title="Device enrolment QR code" />
        ) : (
          <div className="flex h-[216px] w-[216px] items-center justify-center rounded-md border border-dashed text-center text-xs text-muted-foreground">
            {buildError}
          </div>
        )}
      </div>

      {mode === "enrol" && (
        <div className="space-y-2">
          <p className="text-[11px] text-muted-foreground">
            Pre-filled from the address <em>this browser</em> used. Correct it
            if the phone reaches the server differently — a laptop on a VPN and
            a handset on wifi often disagree.
          </p>
          <div className="grid grid-cols-[1fr_5rem_5.5rem] gap-2">
            <input
              className={inputCls}
              value={conn.host}
              onChange={(e) => setConn({ ...conn, host: e.target.value })}
              placeholder="ddi.internal.example"
              aria-label="Host"
            />
            <input
              className={inputCls}
              value={conn.port ?? ""}
              onChange={(e) => {
                // Digits only. `Number("8443/")` is NaN, which would reach the
                // URI as a literal ``port=NaN`` the client cannot parse.
                const digits = e.target.value.replace(/\D/g, "").slice(0, 5);
                setConn({ ...conn, port: digits ? Number(digits) : null });
              }}
              placeholder="port"
              inputMode="numeric"
              aria-label="Port"
            />
            <select
              className={inputCls}
              value={conn.scheme}
              onChange={(e) =>
                setConn({
                  ...conn,
                  scheme: e.target.value === "http" ? "http" : "https",
                })
              }
              aria-label="Scheme"
            >
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
          </div>

          {pinnable ? (
            <label className="flex items-start gap-2 text-[11px] text-muted-foreground">
              <input
                type="checkbox"
                checked={pinCert}
                onChange={(e) => setPinCert(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                Pin this server&apos;s certificate — the app verifies what it is
                offered against{" "}
                <code className="break-all font-mono text-[10px]">
                  {displayFingerprint(pinnable)}
                </code>
                . Untick if something in front of SpatiumDDI re-terminates TLS,
                since the app would then report a mismatch on a correct setup.
              </span>
            </label>
          ) : (
            // A failed lookup must not read as a still-loading one: both leave
            // the code unpinned, and only one of them is going to change.
            <p className="text-[11px] text-muted-foreground">
              {ctxLoading
                ? "Checking whether this server can pin its certificate…"
                : ctxError
                  ? "Couldn't check this server's certificate, so the code below carries no fingerprint — the app will ask you to confirm the certificate by hand."
                  : (ctx?.fingerprint_unavailable_reason ??
                    "This server cannot state the certificate it presents, so the code below carries no fingerprint.")}
            </p>
          )}
        </div>
      )}

      {mode === "token" && (
        <p className="text-center text-[11px] text-muted-foreground">
          The token on its own. Use this if the app is already pointed at this
          server.
        </p>
      )}
    </div>
  );
}

// Shown after a successful create. The raw token is NEVER retrievable
// again so we force the operator to copy it, and close the modal only
// after explicit confirmation.

function RevealTokenModal({
  token,
  onClose,
}: {
  token: ApiTokenCreated;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [visible, setVisible] = useState(false);

  async function copy() {
    const ok = await copyToClipboard(token.token);
    if (ok) {
      setCopied(true);
      setCopyFailed(false);
      setTimeout(() => setCopied(false), 2000);
    } else {
      // Both paths failed — reveal the value and prompt the user to
      // copy it manually. Don't silently swallow.
      setVisible(true);
      setCopyFailed(true);
    }
  }

  return (
    <Modal title={`Token "${token.name}" — copy now`} onClose={onClose}>
      <div className="space-y-4">
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          This is the <strong>only time</strong> the raw token is visible.
          SpatiumDDI stores only a hash — if you lose this value, delete the
          token and create a new one.
        </div>
        {copyFailed && (
          <div className="rounded-md border border-rose-500/40 bg-rose-500/5 px-3 py-2 text-xs text-rose-700 dark:text-rose-300">
            Automatic copy failed (browser blocked the clipboard API — usually
            because the page is served over plain HTTP on a non-localhost host).
            The token is now visible below — select it manually and copy with{" "}
            <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>C</kbd>.
          </div>
        )}
        <div className="flex items-center gap-2 rounded-md border bg-muted/30 px-3 py-2 font-mono text-sm">
          <code className="flex-1 truncate" title={token.token}>
            {visible ? token.token : "•".repeat(40)}
          </code>
          <button
            type="button"
            onClick={() => setVisible((v) => !v)}
            className="rounded p-1 text-muted-foreground hover:bg-background hover:text-foreground"
            title={visible ? "Hide" : "Reveal"}
          >
            {visible ? (
              <EyeOff className="h-3.5 w-3.5" />
            ) : (
              <Eye className="h-3.5 w-3.5" />
            )}
          </button>
          <button
            type="button"
            onClick={copy}
            className="rounded p-1 text-muted-foreground hover:bg-background hover:text-foreground"
            title="Copy to clipboard"
          >
            <Copy className="h-3.5 w-3.5" />
          </button>
        </div>
        <p className="text-xs text-muted-foreground">
          Use as a Bearer token:{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">
            Authorization: Bearer {token.prefix}…
          </code>
        </p>
        <EnrolmentQr token={token} />
        <div className="flex justify-end gap-2 pt-1">
          <button
            onClick={onClose}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            {copied ? "Copied — Done" : "I've copied it — Done"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export function ApiTokensPage() {
  const qc = useQueryClient();
  const { data: tokens = [], isLoading } = useQuery({
    queryKey: ["api-tokens"],
    queryFn: apiTokensApi.list,
  });
  const [showCreate, setShowCreate] = useState(false);
  const [justCreated, setJustCreated] = useState<ApiTokenCreated | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ApiToken | null>(null);

  const toggleMut = useMutation({
    mutationFn: (t: ApiToken) =>
      apiTokensApi.update(t.id, { is_active: !t.is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-tokens"] }),
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => apiTokensApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
      setConfirmDelete(null);
    },
  });

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">API Tokens</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Long-lived bearer credentials for scripts and automation. Each
              token inherits its owner's permissions.
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3.5 w-3.5" />
            New Token
          </button>
        </div>

        <div className="rounded-lg border bg-card">
          {isLoading ? (
            <p className="px-4 py-6 text-sm text-muted-foreground">Loading…</p>
          ) : tokens.length === 0 ? (
            <p className="px-4 py-6 text-sm text-muted-foreground">
              No tokens yet. Create one to use SpatiumDDI's REST API from
              scripts or CI.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Prefix</th>
                  <th className="px-3 py-2">Scopes</th>
                  <th className="px-3 py-2">Expires</th>
                  <th className="px-3 py-2">Last Used</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {tokens.map((t) => (
                  <tr key={t.id} className="border-b last:border-0">
                    <td className="px-3 py-2">
                      <div className="font-medium">{t.name}</div>
                      {t.description && (
                        <div
                          className="truncate text-xs text-muted-foreground"
                          title={t.description}
                        >
                          {t.description}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{t.prefix}…</td>
                    <td className="px-3 py-2">
                      <ScopeChips scopes={t.scopes} />
                      {t.resource_grants && t.resource_grants.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {t.resource_grants.map((g, i) => (
                            <span
                              key={i}
                              className="rounded bg-violet-100 px-1.5 py-0.5 text-[10px] font-medium text-violet-700 dark:bg-violet-900/30 dark:text-violet-300"
                              title={`Bound to ${g.resource_type} ${g.resource_id} (${g.action})`}
                            >
                              {g.action}:{g.resource_type}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {t.expires_at ? (
                        <ExpiryCell iso={t.expires_at} />
                      ) : (
                        <span className="text-amber-600 dark:text-amber-400">
                          Never
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {t.last_used_at
                        ? new Date(t.last_used_at).toLocaleString()
                        : "—"}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={cn(
                          "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium",
                          t.is_active
                            ? "bg-emerald-500/15 text-emerald-600"
                            : "bg-muted text-muted-foreground",
                        )}
                      >
                        {t.is_active ? "Active" : "Revoked"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-1">
                        <button
                          onClick={() => toggleMut.mutate(t)}
                          className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                          title={t.is_active ? "Revoke" : "Re-enable"}
                        >
                          {t.is_active ? (
                            <PowerOff className="h-3.5 w-3.5" />
                          ) : (
                            <Power className="h-3.5 w-3.5" />
                          )}
                        </button>
                        <button
                          onClick={() => setConfirmDelete(t)}
                          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                          title="Delete"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {showCreate && (
          <CreateTokenModal
            onClose={() => setShowCreate(false)}
            onCreated={(t) => {
              setShowCreate(false);
              setJustCreated(t);
            }}
          />
        )}
        {justCreated && (
          <RevealTokenModal
            token={justCreated}
            onClose={() => setJustCreated(null)}
          />
        )}
        {confirmDelete && (
          <Modal
            title="Delete API Token"
            onClose={() => setConfirmDelete(null)}
          >
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Permanently delete{" "}
                <strong className="text-foreground">
                  {confirmDelete.name}
                </strong>
                ? Any script still using it will start getting 401 responses.
              </p>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setConfirmDelete(null)}
                  className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
                >
                  Cancel
                </button>
                <button
                  onClick={() => deleteMut.mutate(confirmDelete.id)}
                  disabled={deleteMut.isPending}
                  className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
                >
                  {deleteMut.isPending ? "Deleting…" : "Delete"}
                </button>
              </div>
            </div>
          </Modal>
        )}
      </div>
    </div>
  );
}

function ScopeChips({ scopes }: { scopes: ApiTokenScope[] | undefined }) {
  // Empty list = no restriction; render an explicit "full access"
  // hint rather than blank so operators can tell the difference
  // between "scopes weren't loaded" and "no scope restriction".
  if (!scopes || scopes.length === 0) {
    return (
      <span
        className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
        title="No scope restriction — token inherits the owner's full RBAC."
      >
        full
      </span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((s) => {
        const meta = API_TOKEN_SCOPES.find((m) => m.value === s);
        return (
          <span
            key={s}
            className="inline-flex items-center rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] text-primary"
            title={meta?.hint ?? s}
          >
            {s}
          </span>
        );
      })}
    </div>
  );
}

function ExpiryCell({ iso }: { iso: string }) {
  const expires = new Date(iso);
  const now = Date.now();
  const daysOut = Math.round((expires.getTime() - now) / (24 * 60 * 60 * 1000));
  let cls = "";
  if (daysOut < 0) cls = "text-destructive";
  else if (daysOut < 7) cls = "text-amber-600 dark:text-amber-400";
  else cls = "text-muted-foreground";
  return (
    <span className={cls} title={expires.toLocaleString()}>
      {daysOut < 0
        ? `Expired ${-daysOut}d ago`
        : daysOut === 0
          ? "Expires today"
          : `In ${daysOut}d`}
    </span>
  );
}

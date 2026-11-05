import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  KeySquare,
  Pencil,
  Plus,
  Power,
  PowerOff,
  Trash2,
} from "lucide-react";
import { ListReadError } from "@/components/ui/list-read-error";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import {
  apiTokensApi,
  formatDialogError,
  groupsApi,
  serviceAccountsApi,
  type ApiToken,
  type ApiTokenCreated,
  type ServiceAccount,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { CreateTokenModal, RevealTokenModal } from "./ApiTokensPage";

// Service accounts (#2144): API principals for external systems — Home
// Assistant, Ansible, a monitoring poller, CI. No password and no sign-in;
// groups (and so roles) like a user; tokens a superadmin mints here. Every
// route behind this page is superadmin-only, so every control is gated on it.

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

function GroupPicker({
  selected,
  onChange,
}: {
  selected: string[];
  onChange: (ids: string[]) => void;
}) {
  const groups = useQuery({ queryKey: ["groups"], queryFn: groupsApi.list });
  if (groups.isError) {
    return <ListReadError error={groups.error} what="groups" />;
  }
  const rows = groups.data ?? [];
  return (
    <div className="max-h-48 space-y-1 overflow-auto rounded-md border p-2">
      {rows.length === 0 && (
        <p className="text-xs text-muted-foreground">
          {groups.isLoading ? "Loading…" : "No groups yet."}
        </p>
      )}
      {rows.map((g) => (
        <label
          key={g.id}
          className="flex cursor-pointer select-none items-start gap-2 text-sm"
        >
          <input
            type="checkbox"
            className="mt-0.5 h-3.5 w-3.5"
            checked={selected.includes(g.id)}
            onChange={(e) =>
              onChange(
                e.target.checked
                  ? [...selected, g.id]
                  : selected.filter((x) => x !== g.id),
              )
            }
          />
          <span className="min-w-0">
            <span className="font-medium">{g.name}</span>
            {g.description && (
              <span className="block truncate text-xs text-muted-foreground">
                {g.description}
              </span>
            )}
          </span>
        </label>
      ))}
    </div>
  );
}

const GROUPS_HINT =
  "Its permissions are its groups' roles, as for a user. A group granting superadmin is refused: give it a role carrying only what the external system needs.";

function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
      {error}
    </div>
  );
}

// ── Create / edit ──────────────────────────────────────────────────────────

function CreateServiceAccountModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () =>
      serviceAccountsApi.create({
        username,
        display_name: displayName,
        group_ids: groupIds,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["service-accounts"] });
      onClose();
    },
    onError: (err: unknown) =>
      setError(formatDialogError(err, "Failed to create service account.")),
  });
  return (
    <Modal title="New Service Account" onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          mut.mutate();
        }}
      >
        <Field
          label="Name"
          hint="Letters, digits, '.', '_' or '-'. Shares the user namespace, and never signs in."
        >
          <input
            className={inputCls}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="e.g. homeassistant"
            required
            autoFocus
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="e.g. Home Assistant on ha.lan"
          />
        </Field>
        <Field label="Groups" hint={GROUPS_HINT}>
          <GroupPicker selected={groupIds} onChange={setGroupIds} />
        </Field>
        <ErrorBox error={error} />
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
            disabled={!username.trim() || mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditServiceAccountModal({
  account,
  onClose,
}: {
  account: ServiceAccount;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [displayName, setDisplayName] = useState(account.display_name);
  const [groupIds, setGroupIds] = useState<string[]>(
    account.groups.map((g) => g.id),
  );
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () =>
      serviceAccountsApi.update(account.id, {
        display_name: displayName,
        group_ids: groupIds,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["service-accounts"] });
      onClose();
    },
    onError: (err: unknown) =>
      setError(formatDialogError(err, "Failed to save service account.")),
  });
  return (
    <Modal title={`Edit ${account.username}`} onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          mut.mutate();
        }}
      >
        <Field label="Description">
          <input
            className={inputCls}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            autoFocus
          />
        </Field>
        <Field label="Groups" hint={GROUPS_HINT}>
          <GroupPicker selected={groupIds} onChange={setGroupIds} />
        </Field>
        <ErrorBox error={error} />
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
            disabled={mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Tokens ─────────────────────────────────────────────────────────────────

function formatWhen(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}

function tokenStatus(t: ApiToken): string {
  if (!t.is_active) return "Revoked";
  if (t.expires_at && new Date(t.expires_at).getTime() <= Date.now())
    return "Expired";
  return "Active";
}

function TokensModal({
  account,
  onClose,
}: {
  account: ServiceAccount;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ApiToken | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = ["service-accounts", account.id, "tokens"];
  const tokens = useQuery({
    queryKey: key,
    queryFn: () => serviceAccountsApi.listTokens(account.id),
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["service-accounts"] });
    qc.invalidateQueries({ queryKey: ["api-tokens"] });
  };
  const revoke = useMutation({
    mutationFn: (t: ApiToken) =>
      apiTokensApi.update(t.id, { is_active: false }),
    onSuccess: refresh,
    onError: (err: unknown) =>
      setError(formatDialogError(err, "Failed to revoke token.")),
  });
  const remove = useMutation({
    mutationFn: (t: ApiToken) => apiTokensApi.delete(t.id),
    onSuccess: () => {
      setConfirmDelete(null);
      refresh();
    },
    onError: (err: unknown) => {
      setConfirmDelete(null);
      setError(formatDialogError(err, "Failed to delete token."));
    },
  });
  const rows = tokens.data ?? [];

  return (
    <>
      <Modal title={`Tokens — ${account.username}`} onClose={onClose} wide>
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="min-w-0 flex-1 text-xs text-muted-foreground">
              Each token authenticates as this account, narrowed by its scopes
              and bindings. Revoked or deleted tokens stop working at once.
            </p>
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              disabled={!account.is_active}
              title={
                account.is_active
                  ? undefined
                  : "The account is disabled — enable it first"
              }
              className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" />
              New Token
            </button>
          </div>
          <ErrorBox error={error} />
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full min-w-[560px] text-sm">
              <thead className="border-b text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Prefix</th>
                  <th className="px-3 py-2">Expires</th>
                  <th className="px-3 py-2">Last Used</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {tokens.isLoading && (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-3 py-4 text-center text-muted-foreground"
                    >
                      Loading…
                    </td>
                  </tr>
                )}
                {tokens.isError && (
                  <tr>
                    <td colSpan={6} className="px-3 py-4 text-center">
                      <ListReadError error={tokens.error} what="tokens" />
                    </td>
                  </tr>
                )}
                {!tokens.isLoading && !tokens.isError && rows.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-3 py-4 text-center text-muted-foreground"
                    >
                      No tokens yet.
                    </td>
                  </tr>
                )}
                {rows.map((t) => (
                  <tr key={t.id} className="border-b last:border-0">
                    <td className="px-3 py-2">
                      <div className="font-medium">{t.name}</div>
                      {t.scopes.length > 0 && (
                        <div className="text-[11px] text-muted-foreground">
                          {t.scopes.join(", ")}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{t.prefix}…</td>
                    <td className="px-3 py-2 text-xs">
                      {t.expires_at ? formatWhen(t.expires_at) : "Never"}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {formatWhen(t.last_used_at)}
                    </td>
                    <td className="px-3 py-2 text-xs">{tokenStatus(t)}</td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-1">
                        {t.is_active && (
                          <button
                            type="button"
                            onClick={() => revoke.mutate(t)}
                            className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                            title="Revoke"
                            aria-label={`Revoke ${t.name}`}
                          >
                            <PowerOff className="h-3.5 w-3.5" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setConfirmDelete(t)}
                          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                          title="Delete"
                          aria-label={`Delete ${t.name}`}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Modal>
      {showCreate && (
        <CreateTokenModal
          title={`New Token — ${account.username}`}
          ownerName={account.username}
          create={(body) => serviceAccountsApi.createToken(account.id, body)}
          onClose={() => setShowCreate(false)}
          onCreated={(t) => {
            setShowCreate(false);
            qc.invalidateQueries({ queryKey: key });
            setCreated(t);
          }}
        />
      )}
      {created && (
        <RevealTokenModal token={created} onClose={() => setCreated(null)} />
      )}
      <ConfirmModal
        open={confirmDelete !== null}
        title="Delete API Token"
        tone="destructive"
        autoFocusCancel
        confirmLabel="Delete"
        loading={remove.isPending}
        message={
          <>
            Permanently delete{" "}
            <strong className="text-foreground">{confirmDelete?.name}</strong>?
            Anything still using it gets 401 from now on.
          </>
        }
        onConfirm={() => confirmDelete && remove.mutate(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
      />
    </>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export function ServiceAccountsPage() {
  const qc = useQueryClient();
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<ServiceAccount | null>(null);
  const [tokensFor, setTokensFor] = useState<ServiceAccount | null>(null);
  const [toggle, setToggle] = useState<ServiceAccount | null>(null);
  const [remove, setRemove] = useState<ServiceAccount | null>(null);
  const [error, setError] = useState<string | null>(null);
  const accounts = useQuery({
    queryKey: ["service-accounts"],
    queryFn: serviceAccountsApi.list,
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["service-accounts"] });
    qc.invalidateQueries({ queryKey: ["api-tokens"] });
  };
  const toggleMut = useMutation({
    mutationFn: (a: ServiceAccount) =>
      serviceAccountsApi.update(a.id, { is_active: !a.is_active }),
    onSuccess: () => {
      setToggle(null);
      refresh();
    },
    onError: (err: unknown) => {
      setToggle(null);
      setError(formatDialogError(err, "Failed to update service account."));
    },
  });
  const deleteMut = useMutation({
    mutationFn: (a: ServiceAccount) => serviceAccountsApi.delete(a.id),
    onSuccess: () => {
      setRemove(null);
      refresh();
    },
    onError: (err: unknown) => {
      setRemove(null);
      setError(formatDialogError(err, "Failed to delete service account."));
    },
  });
  const rows = accounts.data ?? [];

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">
              Service Accounts
            </h1>
            <p className="mt-1 text-xs text-muted-foreground">
              API access for external systems — Home Assistant, Ansible,
              monitoring, CI — without a fake person. A service account has no
              password and cannot sign in; it holds groups like a user and
              authenticates only with the tokens minted here.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            {...superadminGate}
          >
            <Plus className="h-3.5 w-3.5" />
            New Service Account
          </button>
        </div>
        <ErrorBox error={error} />

        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="border-b bg-muted/50 text-xs">
                <th className="px-4 py-3 text-left font-medium">Name</th>
                <th className="px-4 py-3 text-left font-medium">Groups</th>
                <th className="px-4 py-3 text-left font-medium">Tokens</th>
                <th className="px-4 py-3 text-left font-medium">Last Used</th>
                <th className="px-4 py-3 text-left font-medium">Next Expiry</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {accounts.isLoading && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-6 text-center text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!accounts.isLoading && !rows.length && accounts.isError && (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center">
                    <ListReadError
                      error={accounts.error}
                      what="service accounts"
                    />
                  </td>
                </tr>
              )}
              {!accounts.isLoading && !accounts.isError && !rows.length && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-6 text-center text-muted-foreground"
                  >
                    No service accounts yet.
                  </td>
                </tr>
              )}
              {rows.map((a) => (
                <tr key={a.id} className="border-b last:border-0">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 font-mono font-medium">
                      <Bot className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      <span className="break-all">{a.username}</span>
                    </div>
                    {a.display_name && a.display_name !== a.username && (
                      <div className="text-xs text-muted-foreground">
                        {a.display_name}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {a.groups.length === 0 ? (
                        <span className="text-xs text-muted-foreground">
                          None — it can do nothing yet
                        </span>
                      ) : (
                        a.groups.map((g) => (
                          <span
                            key={g.id}
                            className="rounded bg-muted px-1.5 py-0.5 text-[11px]"
                          >
                            {g.name}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {a.active_token_count} active
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {formatWhen(a.last_used_at)}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {a.next_token_expiry
                      ? formatWhen(a.next_token_expiry)
                      : a.active_token_count > 0
                        ? "Never"
                        : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={cn(
                        "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium",
                        a.is_active
                          ? "bg-emerald-500/15 text-emerald-600"
                          : "bg-muted text-muted-foreground",
                      )}
                    >
                      {a.is_active ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      <button
                        type="button"
                        onClick={() => setTokensFor(a)}
                        className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                        title="Tokens"
                        aria-label={`Tokens for ${a.username}`}
                        {...superadminGate}
                      >
                        <KeySquare className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => setEdit(a)}
                        className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                        title="Edit"
                        aria-label={`Edit ${a.username}`}
                        {...superadminGate}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => setToggle(a)}
                        className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                        title={a.is_active ? "Disable" : "Enable"}
                        aria-label={`${a.is_active ? "Disable" : "Enable"} ${a.username}`}
                        {...superadminGate}
                      >
                        {a.is_active ? (
                          <PowerOff className="h-3.5 w-3.5" />
                        ) : (
                          <Power className="h-3.5 w-3.5" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() => setRemove(a)}
                        className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:cursor-not-allowed disabled:opacity-40"
                        title="Delete"
                        aria-label={`Delete ${a.username}`}
                        {...superadminGate}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <CreateServiceAccountModal onClose={() => setShowCreate(false)} />
      )}
      {edit && (
        <EditServiceAccountModal account={edit} onClose={() => setEdit(null)} />
      )}
      {tokensFor && (
        <TokensModal account={tokensFor} onClose={() => setTokensFor(null)} />
      )}
      <ConfirmModal
        open={toggle !== null}
        title={
          toggle?.is_active
            ? "Disable Service Account"
            : "Enable Service Account"
        }
        tone={toggle?.is_active ? "destructive" : "default"}
        confirmLabel={toggle?.is_active ? "Disable" : "Enable"}
        loading={toggleMut.isPending}
        message={
          toggle?.is_active ? (
            <>
              Disable{" "}
              <strong className="text-foreground">{toggle.username}</strong>?
              Every token it holds is revoked now, and stays revoked if you
              enable it again — mint new ones then.
            </>
          ) : (
            <>
              Enable{" "}
              <strong className="text-foreground">{toggle?.username}</strong>?
              It starts with no live tokens; mint one under Tokens.
            </>
          )
        }
        onConfirm={() => toggle && toggleMut.mutate(toggle)}
        onClose={() => setToggle(null)}
      />
      <ConfirmModal
        open={remove !== null}
        title="Delete Service Account"
        tone="destructive"
        autoFocusCancel
        confirmLabel="Delete"
        loading={deleteMut.isPending}
        message={
          <>
            Permanently delete{" "}
            <strong className="text-foreground">{remove?.username}</strong> and
            every token it holds? Its audit history stays.
          </>
        }
        onConfirm={() => remove && deleteMut.mutate(remove)}
        onClose={() => setRemove(null)}
      />
    </div>
  );
}

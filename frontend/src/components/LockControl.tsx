import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Lock, Unlock } from "lucide-react";

import {
  formatApiError,
  locksApi,
  type LockableType,
  type LockFields,
  type LockLevel,
} from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";
import { lockTitle } from "@/lib/locks";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";

// Padlock + lock/unlock action for an IPAM / DNS / DHCP object (#3361).
//
// ``LockBadge`` is the read half: a padlock with the level, who locked it and
// why in its title, shown on rows and detail headers. ``LockControl`` adds the
// action, behind the ``lock`` grant on the object's type, with a reason dialog
// (a reason is required to lock and to unlock). The action is hidden for an
// integration-owned object, which the server refuses to lock.

// The RBAC type a ``lock`` grant is checked against: a view is locked with
// ``lock`` on ``dns_group``.
const PERMISSION_TYPE: Record<LockableType, string> = {
  ip_space: "ip_space",
  ip_block: "ip_block",
  subnet: "subnet",
  ip_address: "ip_address",
  dns_group: "dns_group",
  dns_view: "dns_group",
  dns_zone: "dns_zone",
  dns_record: "dns_record",
  dhcp_scope: "dhcp_scope",
  dhcp_static: "dhcp_static",
};

export function LockBadge({
  resource,
  className,
}: {
  resource: LockFields;
  className?: string;
}) {
  const title = lockTitle(resource);
  if (!title) return null;
  return (
    <span
      title={title}
      aria-label={title}
      data-testid="lock-badge"
      className={
        className ??
        "inline-flex items-center gap-1 rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wider text-amber-700 dark:bg-amber-950/30 dark:text-amber-400"
      }
    >
      <Lock className="h-3 w-3" />
      {resource.lock_level}
    </span>
  );
}

export function LockDialog({
  type,
  id,
  label,
  locked,
  onClose,
  onDone,
}: {
  type: LockableType;
  id: string;
  label: string;
  locked: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const [level, setLevel] = useState<LockLevel>("edit");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const mut = useMutation({
    mutationFn: () =>
      locked
        ? locksApi.unlock(type, id, reason.trim()).then(() => undefined)
        : locksApi
            .lock(type, id, {
              level,
              reason: reason.trim(),
              expires_at: expires ? new Date(expires).toISOString() : null,
            })
            .then(() => undefined),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });
  const title = locked ? `Unlock ${label}` : `Lock ${label}`;
  return (
    <Modal title={title} onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (reason.trim()) mut.mutate();
        }}
      >
        {!locked && (
          <>
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Level</span>
              <select
                value={level}
                onChange={(e) => setLevel(e.target.value as LockLevel)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              >
                <option value="edit">
                  Edit: freeze operative fields, block delete
                </option>
                <option value="delete">Delete: block delete only</option>
              </select>
            </label>
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Expires (optional)</span>
              <input
                type="datetime-local"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              />
            </label>
          </>
        )}
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Reason (required)</span>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
            placeholder={
              locked ? "Why the freeze is lifted" : "Change freeze, audit hold…"
            }
          />
        </label>
        {mut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {formatApiError(mut.error, "Could not change the lock")}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <HeaderButton type="button" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            type="submit"
            variant="primary"
            disabled={!reason.trim() || mut.isPending}
          >
            {locked ? "Unlock" : "Lock"}
          </HeaderButton>
        </div>
      </form>
    </Modal>
  );
}

export function LockControl({
  type,
  resource,
  label,
  onChanged,
  integrationOwned = false,
  showBadge = true,
}: {
  type: LockableType;
  resource: LockFields & { id: string };
  label: string;
  onChanged: () => void;
  /** An integration-owned object cannot be locked: the action is hidden. */
  integrationOwned?: boolean;
  /** Skip the padlock when the page already shows one beside the title. */
  showBadge?: boolean;
}) {
  const perms = usePermissions();
  const [open, setOpen] = useState(false);
  const locked = !!resource.lock_level;
  const allowed = perms.can("lock", PERMISSION_TYPE[type], resource.id);
  const badge = showBadge ? <LockBadge resource={resource} /> : null;
  if (integrationOwned || !allowed) return badge;
  return (
    <>
      {badge}
      <HeaderButton
        icon={locked ? Unlock : Lock}
        onClick={() => setOpen(true)}
        title={locked ? "Remove the lock (a reason is required)" : "Lock"}
      >
        {locked ? "Unlock" : "Lock"}
      </HeaderButton>
      {open && (
        <LockDialog
          type={type}
          id={resource.id}
          label={label}
          locked={locked}
          onClose={() => setOpen(false)}
          onDone={onChanged}
        />
      )}
    </>
  );
}

/**
 * ResizeSubnetModal + ResizeBlockModal — grow-only CIDR widening with
 * preview + typed-confirmation gates.
 *
 * Design notes:
 * - The flow is preview → confirm, mirroring ImportModal. Preview hits
 *   /resize/preview; confirm only enables once the server returned a
 *   preview with zero conflicts AND the user typed the new CIDR into the
 *   confirmation text box. This is the "really really sure" gate for a
 *   destructive operation — a bad resize silently rewrites the source of
 *   truth for a whole network.
 * - Renamed placeholders are always preserved server-side, so the
 *   "Replace default-named network/broadcast rows" checkbox is ONLY about
 *   the rows with default hostnames. Tooltip makes this clear.
 * - The confirm button is hidden on conflict, not just disabled, so the
 *   user has no false sense that they can force-commit.
 */

import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, AlertTriangle, CheckCircle2, X } from "lucide-react";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import {
  formatApiError,
  ipamApi,
  type BlockResizeCommitResponse,
  type BlockResizePreviewResponse,
  type IPBlock,
  type ResizeConflict,
  type Subnet,
  type SubnetResizeCommitResponse,
  type SubnetResizePreviewResponse,
} from "@/lib/api";

// ── Shared UI bits ────────────────────────────────────────────────────────

function ConflictList({ conflicts }: { conflicts: ResizeConflict[] }) {
  if (conflicts.length === 0) return null;
  return (
    <div className="rounded border border-red-300 bg-red-50 p-3 dark:border-red-900 dark:bg-red-900/20">
      <div className="mb-1 flex items-center gap-2 text-sm font-medium text-red-900 dark:text-red-200">
        <AlertCircle className="h-4 w-4" />
        {conflicts.length} conflict{conflicts.length === 1 ? "" : "s"} — commit
        disabled
      </div>
      <ul className="list-disc pl-5 text-xs text-red-800 dark:text-red-300">
        {conflicts.map((c, i) => (
          <li key={i}>
            <span className="font-mono">{c.type}</span>: {c.detail}
          </li>
        ))}
      </ul>
    </div>
  );
}

function WarningList({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="rounded border border-amber-300 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-900/20">
      <div className="mb-1 flex items-center gap-2 text-sm font-medium text-amber-900 dark:text-amber-200">
        <AlertTriangle className="h-4 w-4" />
        Warnings
      </div>
      <ul className="list-disc pl-5 text-xs text-amber-900 dark:text-amber-200">
        {warnings.map((w, i) => (
          <li key={i}>{w}</li>
        ))}
      </ul>
    </div>
  );
}

function BigYellowBanner({ newCidr }: { newCidr: string }) {
  return (
    <div className="rounded border-2 border-yellow-400 bg-yellow-50 p-3 text-xs text-yellow-900 dark:border-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-100">
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
        <div className="space-y-1">
          <p className="font-semibold">
            This operation rewrites the authoritative network definition.
          </p>
          <ul className="list-disc pl-4 space-y-0.5">
            <li>
              Every client on this network must be reconfigured with the new
              netmask (<span className="font-mono">{newCidr}</span>).
            </li>
            <li>
              Routers, firewalls, and any hard-coded references to the old CIDR
              must be updated manually.
            </li>
            <li>
              This cannot be automatically undone. To revert, you must run the
              resize again with the original CIDR — which is only legal if the
              new smaller subnet is still a valid grow-target of whatever is
              there now.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function TypeToConfirm({
  expected,
  value,
  onChange,
}: {
  expected: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium">
        Type the new CIDR to confirm:{" "}
        <span className="font-mono">{expected}</span>
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={expected}
        spellCheck={false}
        autoComplete="off"
        className="w-full rounded border bg-background px-2 py-1 text-sm font-mono focus:ring-inset"
      />
    </div>
  );
}

function ModalShell({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);
  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="flex max-h-[90vh] w-full max-w-[95vw] sm:max-w-[760px] flex-col rounded-lg bg-background shadow-xl focus:outline-none"
        style={dialogStyle}
      >
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-center justify-between border-b p-4",
            dragHandleProps.className,
          )}
        >
          <h2 {...titleProps} className="text-base font-semibold">
            {title}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">{children}</div>
        <div className="flex flex-wrap justify-end gap-2 border-t p-3">
          {footer}
        </div>
      </div>
    </div>
  );
}

// ── ResizeSubnetModal ─────────────────────────────────────────────────────

export function ResizeSubnetModal({
  subnet,
  onClose,
  onCommitted,
}: {
  subnet: Subnet;
  onClose: () => void;
  onCommitted?: (result: SubnetResizeCommitResponse) => void;
}) {
  const qc = useQueryClient();
  const [newCidr, setNewCidr] = useState("");
  const [moveGateway, setMoveGateway] = useState(false);
  const [replaceDefaults, setReplaceDefaults] = useState(true);
  const [preview, setPreview] = useState<SubnetResizePreviewResponse | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [committed, setCommitted] = useState<SubnetResizeCommitResponse | null>(
    null,
  );

  const previewMut = useMutation({
    mutationFn: () =>
      ipamApi.resizeSubnetPreview(subnet.id, {
        new_cidr: newCidr.trim(),
        // Forward so the server can surface a conflict when the CIDR has
        // no usable host range (/31/32/127/128) — preview must reflect the
        // same ask commit will receive.
        move_gateway_to_first_usable: moveGateway,
      }),
    onSuccess: (data) => {
      setPreview(data);
      setError(null);
      setConfirmText("");
    },
    onError: (err) => {
      setPreview(null);
      setError(formatApiError(err, "Preview failed"));
    },
  });

  const commitMut = useMutation({
    mutationFn: () =>
      ipamApi.resizeSubnetCommit(subnet.id, {
        new_cidr: newCidr.trim(),
        move_gateway_to_first_usable: moveGateway,
        replace_default_placeholders: replaceDefaults,
      }),
    onSuccess: (data) => {
      setCommitted(data);
      qc.invalidateQueries({ queryKey: ["subnets"] });
      qc.invalidateQueries({ queryKey: ["subnet", subnet.id] });
      qc.invalidateQueries({ queryKey: ["addresses"] });
      qc.invalidateQueries({ queryKey: ["blocks"] });
      qc.invalidateQueries({ queryKey: ["spaces"] });
      qc.invalidateQueries({ queryKey: ["dhcp-scopes"] });
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.invalidateQueries({ queryKey: ["dns-records"] });
      onCommitted?.(data);
    },
    onError: (err) => {
      setError(formatApiError(err, "Commit failed"));
    },
  });

  const canPreview = useMemo(() => {
    const v = newCidr.trim();
    // Naive check — the server does authoritative validation. We just want
    // to avoid pinging the API with obvious junk.
    return /\//.test(v) && v !== subnet.network;
  }, [newCidr, subnet.network]);

  const hasConflicts = (preview?.conflicts?.length ?? 0) > 0;
  const confirmMatches =
    preview && confirmText.trim() === preview.new_cidr.trim();
  const canCommit =
    preview !== null &&
    !hasConflicts &&
    !!confirmMatches &&
    !commitMut.isPending;

  if (committed) {
    return (
      <ModalShell
        title="Resize complete"
        onClose={onClose}
        footer={
          <button
            onClick={onClose}
            className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
          >
            Close
          </button>
        }
      >
        <div className="rounded border border-green-300 bg-green-50 p-3 dark:border-green-900 dark:bg-green-900/20">
          <div className="flex items-center gap-2 text-sm font-medium text-green-900 dark:text-green-200">
            <CheckCircle2 className="h-4 w-4" />
            {committed.old_cidr} → {committed.new_cidr}
          </div>
          <ul className="mt-2 list-disc pl-5 text-xs text-green-900 dark:text-green-200 space-y-0.5">
            {committed.summary.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      </ModalShell>
    );
  }

  return (
    <ModalShell
      title={`Resize subnet ${subnet.network}`}
      onClose={onClose}
      footer={
        <>
          <button
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted"
          >
            Cancel
          </button>
          <button
            disabled={!canPreview || previewMut.isPending}
            onClick={() => previewMut.mutate()}
            className="rounded border bg-muted px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Working…" : "Preview"}
          </button>
          <button
            disabled={!canCommit}
            onClick={() => commitMut.mutate()}
            className="rounded bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {commitMut.isPending ? "Resizing…" : "Resize subnet"}
          </button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium">Current CIDR</label>
          <input
            readOnly
            value={subnet.network}
            className="w-full rounded border bg-muted px-2 py-1 font-mono text-sm"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium">New CIDR</label>
          <input
            type="text"
            value={newCidr}
            onChange={(e) => {
              setNewCidr(e.target.value);
              setPreview(null);
              setConfirmText("");
            }}
            placeholder="e.g. 192.168.0.0/23"
            spellCheck={false}
            autoComplete="off"
            className="w-full rounded border bg-background px-2 py-1 font-mono text-sm focus:ring-inset"
          />
        </div>
      </div>

      <div className="space-y-1">
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={moveGateway}
            onChange={(e) => {
              setMoveGateway(e.target.checked);
              // Preview encodes the gateway-move ask (for the
              // "impossible on /31/32" conflict), so any change
              // invalidates it.
              setPreview(null);
              setConfirmText("");
            }}
          />
          Move gateway to new first-usable IP
        </label>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={replaceDefaults}
            onChange={(e) => setReplaceDefaults(e.target.checked)}
          />
          Replace default-named network/broadcast rows
          <span
            className="ml-1 text-muted-foreground"
            title="Renamed placeholders (e.g. anycast-vip) are always preserved regardless of this setting."
          >
            (?)
          </span>
        </label>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded border border-red-300 bg-red-50 p-2 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {preview && (
        <div className="space-y-3">
          <ConflictList conflicts={preview.conflicts} />
          {!hasConflicts && <BigYellowBanner newCidr={preview.new_cidr} />}

          <div className="rounded border bg-muted/30 p-3 text-xs space-y-2">
            <div className="font-semibold">Blast radius</div>
            <div className="grid grid-cols-2 gap-1.5">
              <RangeRow
                label="Network"
                before={preview.old_network_ip}
                after={preview.new_network_ip}
              />
              <RangeRow
                label="Broadcast"
                before={preview.old_broadcast_ip ?? "—"}
                after={preview.new_broadcast_ip ?? "—"}
              />
              <RangeRow
                label="Total usable IPs"
                before={preview.total_ips_before.toLocaleString()}
                after={preview.total_ips_after.toLocaleString()}
              />
              <RangeRow
                label="Gateway (current)"
                before={preview.gateway_current ?? "—"}
                after={
                  moveGateway
                    ? (preview.gateway_suggested_new_first_usable ?? "—")
                    : (preview.gateway_current ?? "—")
                }
              />
            </div>
            <div className="pt-2 space-y-0.5">
              <div>
                <span className="text-muted-foreground">
                  IP rows in subnet:
                </span>{" "}
                {preview.affected_ip_addresses_total}
              </div>
              <div>
                <span className="text-muted-foreground">DHCP scopes:</span>{" "}
                {preview.affected_dhcp_scopes}
                {preview.affected_dhcp_scopes > 0
                  ? ` (${preview.affected_dhcp_pools} pools, ${preview.affected_dhcp_static_assignments} statics)`
                  : ""}
              </div>
              <div>
                <span className="text-muted-foreground">
                  Active DHCP leases:
                </span>{" "}
                {preview.affected_active_leases}
              </div>
              <div>
                <span className="text-muted-foreground">
                  Auto-generated DNS records:
                </span>{" "}
                {preview.affected_dns_records_auto}
              </div>
              {(preview.reverse_zones_existing.length > 0 ||
                preview.reverse_zones_will_be_created.length > 0) && (
                <div>
                  <span className="text-muted-foreground">Reverse zones:</span>{" "}
                  {preview.reverse_zones_existing.length > 0 && (
                    <span className="font-mono text-[10px]">
                      existing {preview.reverse_zones_existing.join(", ")}
                    </span>
                  )}
                  {preview.reverse_zones_will_be_created.length > 0 && (
                    <span className="font-mono text-[10px]">
                      {" "}
                      + create{" "}
                      {preview.reverse_zones_will_be_created.join(", ")}
                    </span>
                  )}
                </div>
              )}
              {(preview.placeholders_default_named.length > 0 ||
                preview.placeholders_renamed.length > 0) && (
                <div>
                  <span className="text-muted-foreground">Placeholders:</span>{" "}
                  {preview.placeholders_default_named.length} default-named
                  {replaceDefaults
                    ? " (will be replaced)"
                    : " (will stay)"}, {preview.placeholders_renamed.length}{" "}
                  renamed (preserved)
                </div>
              )}
            </div>
          </div>

          <WarningList warnings={preview.warnings} />

          {!hasConflicts && (
            <TypeToConfirm
              expected={preview.new_cidr}
              value={confirmText}
              onChange={setConfirmText}
            />
          )}
        </div>
      )}
    </ModalShell>
  );
}

function RangeRow({
  label,
  before,
  after,
}: {
  label: string;
  before: string;
  after: string;
}) {
  const changed = before !== after;
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-muted-foreground text-[11px] w-28 flex-shrink-0">
        {label}
      </span>
      <span className="font-mono">{before}</span>
      <span className="text-muted-foreground">→</span>
      <span
        className={`font-mono ${changed ? "font-semibold text-blue-700 dark:text-blue-300" : ""}`}
      >
        {after}
      </span>
    </div>
  );
}

// ── ResizeBlockModal ──────────────────────────────────────────────────────

export function ResizeBlockModal({
  block,
  onClose,
  onCommitted,
}: {
  block: IPBlock;
  onClose: () => void;
  onCommitted?: (result: BlockResizeCommitResponse) => void;
}) {
  const qc = useQueryClient();
  const [newCidr, setNewCidr] = useState("");
  const [preview, setPreview] = useState<BlockResizePreviewResponse | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [committed, setCommitted] = useState<BlockResizeCommitResponse | null>(
    null,
  );

  const previewMut = useMutation({
    mutationFn: () =>
      ipamApi.resizeBlockPreview(block.id, { new_cidr: newCidr.trim() }),
    onSuccess: (data) => {
      setPreview(data);
      setError(null);
      setConfirmText("");
    },
    onError: (err) => {
      setPreview(null);
      setError(formatApiError(err, "Preview failed"));
    },
  });

  const commitMut = useMutation({
    mutationFn: () =>
      ipamApi.resizeBlockCommit(block.id, { new_cidr: newCidr.trim() }),
    onSuccess: (data) => {
      setCommitted(data);
      qc.invalidateQueries({ queryKey: ["blocks"] });
      qc.invalidateQueries({ queryKey: ["block", block.id] });
      qc.invalidateQueries({ queryKey: ["subnets"] });
      // Block utilization rollups drive the addresses page + sidebar
      // tree counts; invalidate both so a resize doesn't leave stale
      // figures in the UI.
      qc.invalidateQueries({ queryKey: ["addresses"] });
      qc.invalidateQueries({ queryKey: ["spaces"] });
      onCommitted?.(data);
    },
    onError: (err) => {
      setError(formatApiError(err, "Commit failed"));
    },
  });

  const canPreview = useMemo(() => {
    const v = newCidr.trim();
    return /\//.test(v) && v !== block.network;
  }, [newCidr, block.network]);

  const hasConflicts = (preview?.conflicts?.length ?? 0) > 0;
  const confirmMatches =
    preview && confirmText.trim() === preview.new_cidr.trim();
  const canCommit =
    preview !== null &&
    !hasConflicts &&
    !!confirmMatches &&
    !commitMut.isPending;

  if (committed) {
    return (
      <ModalShell
        title="Resize complete"
        onClose={onClose}
        footer={
          <button
            onClick={onClose}
            className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
          >
            Close
          </button>
        }
      >
        <div className="rounded border border-green-300 bg-green-50 p-3 dark:border-green-900 dark:bg-green-900/20">
          <div className="flex items-center gap-2 text-sm font-medium text-green-900 dark:text-green-200">
            <CheckCircle2 className="h-4 w-4" />
            {committed.old_cidr} → {committed.new_cidr}
          </div>
          <ul className="mt-2 list-disc pl-5 text-xs text-green-900 dark:text-green-200 space-y-0.5">
            {committed.summary.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      </ModalShell>
    );
  }

  return (
    <ModalShell
      title={`Resize block ${block.network}`}
      onClose={onClose}
      footer={
        <>
          <button
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted"
          >
            Cancel
          </button>
          <button
            disabled={!canPreview || previewMut.isPending}
            onClick={() => previewMut.mutate()}
            className="rounded border bg-muted px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Working…" : "Preview"}
          </button>
          <button
            disabled={!canCommit}
            onClick={() => commitMut.mutate()}
            className="rounded bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {commitMut.isPending ? "Resizing…" : "Resize block"}
          </button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium">Current CIDR</label>
          <input
            readOnly
            value={block.network}
            className="w-full rounded border bg-muted px-2 py-1 font-mono text-sm"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium">New CIDR</label>
          <input
            type="text"
            value={newCidr}
            onChange={(e) => {
              setNewCidr(e.target.value);
              setPreview(null);
              setConfirmText("");
            }}
            placeholder="e.g. 10.0.0.0/8"
            spellCheck={false}
            autoComplete="off"
            className="w-full rounded border bg-background px-2 py-1 font-mono text-sm focus:ring-inset"
          />
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded border border-red-300 bg-red-50 p-2 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {preview && (
        <div className="space-y-3">
          <ConflictList conflicts={preview.conflicts} />
          {!hasConflicts && <BigYellowBanner newCidr={preview.new_cidr} />}

          <div className="rounded border bg-muted/30 p-3 text-xs space-y-2">
            <div className="font-semibold">Blast radius</div>
            <div className="grid grid-cols-2 gap-1.5">
              <RangeRow
                label="Network"
                before={preview.old_network_ip}
                after={preview.new_network_ip}
              />
              <RangeRow
                label="Total addresses"
                before={preview.total_ips_before.toLocaleString()}
                after={preview.total_ips_after.toLocaleString()}
              />
            </div>
            <div className="pt-2 space-y-0.5">
              <div>
                <span className="text-muted-foreground">Child blocks:</span>{" "}
                {preview.child_blocks_count}
              </div>
              <div>
                <span className="text-muted-foreground">Child subnets:</span>{" "}
                {preview.child_subnets_count}
              </div>
              <div>
                <span className="text-muted-foreground">
                  IP addresses in descendant subnets:
                </span>{" "}
                {preview.descendant_ip_addresses_total}
              </div>
            </div>
            {(preview.child_blocks.length > 0 ||
              preview.child_subnets.length > 0) && (
              <details className="pt-1">
                <summary className="cursor-pointer text-muted-foreground">
                  Show descendants
                </summary>
                <div className="mt-1 max-h-48 overflow-auto rounded border bg-background p-2 space-y-1 font-mono text-[11px]">
                  {preview.child_blocks.map((c) => (
                    <div key={`b-${c.id}`}>
                      <span className="text-violet-600">block</span> {c.network}
                      {c.name ? ` — ${c.name}` : ""}
                    </div>
                  ))}
                  {preview.child_subnets.map((c) => (
                    <div key={`s-${c.id}`}>
                      <span className="text-blue-600">subnet</span> {c.network}
                      {c.name ? ` — ${c.name}` : ""}
                    </div>
                  ))}
                </div>
              </details>
            )}
          </div>

          <WarningList warnings={preview.warnings} />

          {!hasConflicts && (
            <TypeToConfirm
              expected={preview.new_cidr}
              value={confirmText}
              onChange={setConfirmText}
            />
          )}
        </div>
      )}
    </ModalShell>
  );
}

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { timeBoundGrantsApi, type TimeBoundGrantCreate } from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { StepUpSection } from "@/components/StepUpSection";
import { isStepUpRequired, stepUpBody } from "@/lib/stepup";
import { ResourceIdPicker } from "@/components/ownership/ResourceIdPicker";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// Static action vocabulary (docs/PERMISSIONS.md → Actions). 'admin'
// implies read/write/delete on the type.
const ACTIONS = ["read", "write", "delete", "admin", "*"] as const;

// Static resource_type vocabulary mirrored from docs/PERMISSIONS.md.
// No server enumeration endpoint by design — keep this list in sync
// with the spec table when new resource_types land.
const RESOURCE_TYPES: string[] = [
  "*",
  "ip_space",
  "ip_block",
  "subnet",
  "ip_address",
  "address_set",
  "vlan",
  "vrf",
  "asn",
  "domain",
  "dns_zone",
  "dns_record",
  "dns_group",
  "dns_blocklist",
  "dhcp_server",
  "dhcp_scope",
  "dhcp_pool",
  "dhcp_static",
  "dhcp_client_class",
  "audit_log",
  "user",
  "group",
  "role",
  "auth_provider",
  "custom_field",
  "manage_ipam_templates",
  "settings",
  "api_token",
  "acme_account",
  "customer",
  "site",
  "provider",
  "circuit",
  "network_service",
  "overlay_network",
  "routing_policy",
  "application_category",
  "conformity",
];

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}

// Default the expiry picker to "now + 24h" in the local-tz format a
// datetime-local input expects (YYYY-MM-DDTHH:mm).
function defaultExpiry(): string {
  const d = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

export function CreateTimeBoundGrantModal({
  groupId,
  groupName,
  onClose,
}: {
  groupId: string;
  groupName: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [action, setAction] = useState<string>("read");
  const [resourceType, setResourceType] = useState<string>("subnet");
  const [resourceId, setResourceId] = useState<string>("");
  const [expiresAt, setExpiresAt] = useState<string>(defaultExpiry());
  const [reason, setReason] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  // #1412 — shown once the server says this change makes someone a
  // superadmin; the dialog cannot work that out itself.
  const [needsStepUp, setNeedsStepUp] = useState(false);
  const [stepPassword, setStepPassword] = useState("");
  const [stepTotp, setStepTotp] = useState("");

  const mutation = useMutation({
    mutationFn: () => {
      // datetime-local has no timezone — convert to an absolute ISO
      // string so the server stores the operator's intended instant.
      const iso = new Date(expiresAt).toISOString();
      const payload: TimeBoundGrantCreate = {
        group_id: groupId,
        action,
        resource_type: resourceType,
        resource_id: resourceId.trim() || null,
        expires_at: iso,
        reason: reason.trim(),
        ...(needsStepUp ? stepUpBody(stepPassword, stepTotp) : {}),
      };
      return timeBoundGrantsApi.create(payload);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["time-bound-grants", groupId] });
      onClose();
    },
    onError: (err: unknown) => {
      if (isStepUpRequired(err)) {
        setNeedsStepUp(true);
        setError(null);
        return;
      }
      const msg =
        (err as { response?: { data?: { detail?: unknown } } })?.response?.data
          ?.detail ?? "Failed to create grant";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
    },
  });

  return (
    <Modal
      title={`Grant temporary access — ${groupName}`}
      onClose={onClose}
      wide
    >
      <div className="space-y-4">
        <p className="text-xs text-muted-foreground">
          Grants this group a temporary permission that adds to its role grants.
          The grant auto-revokes at the expiry time you set.
        </p>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Action">
            <select
              className={inputCls}
              value={action}
              onChange={(e) => setAction(e.target.value)}
            >
              {ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Resource type">
            <select
              className={inputCls}
              value={resourceType}
              onChange={(e) => setResourceType(e.target.value)}
            >
              {RESOURCE_TYPES.map((rt) => (
                <option key={rt} value={rt}>
                  {rt}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <Field label="Resource ID (optional — scope to one instance)">
          <ResourceIdPicker
            className={inputCls}
            resourceType={resourceType}
            value={resourceId || null}
            onChange={(id) => setResourceId(id ?? "")}
          />
        </Field>

        <Field label="Expires at">
          <input
            type="datetime-local"
            className={inputCls}
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        </Field>

        <Field label="Reason (recorded in the audit log)">
          <input
            className={inputCls}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g. INC-1234 incident triage"
          />
        </Field>

        {needsStepUp && (
          <StepUpSection
            reason="A * on * grant makes every member of this group a superadmin until it expires. Confirm it's you to grant it."
            password={stepPassword}
            onPassword={setStepPassword}
            totp={stepTotp}
            onTotp={setStepTotp}
          />
        )}
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
            disabled={
              !resourceType ||
              !expiresAt ||
              mutation.isPending ||
              (needsStepUp && !stepPassword && !stepTotp)
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mutation.isPending ? "Granting…" : "Grant access"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

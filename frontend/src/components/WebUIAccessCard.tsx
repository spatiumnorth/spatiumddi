import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Loader2, Lock } from "lucide-react";

import {
  applianceApi,
  firewallApi,
  formatApiError,
  type FirewallWebUIAccess,
  type RemoteDoor,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { cn } from "@/lib/utils";

/**
 * Web UI source restriction (#285 Phase 6) + the cross-setting lockout
 * escalation (#1013).
 *
 * Lifted out of ``pages/appliance/FirewallTab.tsx`` so it can be rendered on
 * its own in a test — the same shape ``SSHSection`` already has, and for the
 * same reason: this card owns two acknowledgement paths whose failure mode is
 * that a modal never opens, which neither review nor ``tsc`` can see.
 */
export function WebUIAccessCard({
  editDisabledReason,
}: {
  /** #1342 — set when the caller may not change Web UI access (it takes
   *  `admin` on `appliance`): Edit… stays, disabled, with this reason. */
  editDisabledReason?: string;
} = {}) {
  const qc = useQueryClient();
  const { data: w } = useQuery({
    queryKey: ["firewall", "web-ui-access"],
    queryFn: firewallApi.getWebUIAccess,
  });
  // #1013 — the OTHER door. Restricting the Web UI is only a console-only
  // lockout when the SSH allow-list also excludes you, and this screen could
  // not see that. ``retry: false``: it is an advisory panel, so a 403 should
  // leave the card rendering rather than retrying.
  const { data: doors } = useQuery({
    queryKey: ["appliance", "remote-access"],
    queryFn: applianceApi.getRemoteAccess,
    retry: false,
    staleTime: 30_000,
  });
  const [editing, setEditing] = useState(false);
  if (!w) return null;
  const excluded = !w.open && !w.caller_covered;
  const sshExcludesMe = Boolean(
    doors && doors.ssh.restricted && !doors.ssh.admits,
  );
  return (
    <div
      className={cn(
        "rounded-md border p-3",
        w.open
          ? "border-border"
          : excluded
            ? "border-rose-500/40 bg-rose-500/5"
            : "border-sky-500/40 bg-sky-500/5",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          {w.open ? (
            <Globe className="mt-0.5 h-5 w-5 text-muted-foreground" />
          ) : (
            <Lock className="mt-0.5 h-5 w-5 text-sky-600 dark:text-sky-400" />
          )}
          <div>
            <div className="text-sm font-medium">
              Web UI access:{" "}
              {w.open
                ? "Open to all"
                : `Restricted to ${w.allowed_cidrs.length} range${
                    w.allowed_cidrs.length === 1 ? "" : "s"
                  }`}
            </div>
            <div className="text-xs text-muted-foreground">
              {w.open
                ? "The Web UI (HTTP/HTTPS) is reachable from any source IP. Restrict it to specific networks to lock it down without an external firewall."
                : "Only these source ranges reach the Web UI — both each appliance's node IP (nftables :80/:443) and the control-plane VIP (MetalLB)."}{" "}
              Your IP: <code>{w.caller_ip ?? "unknown"}</code>
              {excluded && (
                <span className="font-medium text-rose-600 dark:text-rose-400">
                  {" "}
                  — not in the allow-list (you reached this page another way).
                  {doors
                    ? sshExcludesMe
                      ? " SSH is also restricted and excludes this address, so unless you can reach one of those networks another way, only the appliance console reaches this fleet."
                      : " The SSH allow-list does not exclude this address, and the appliance console recovers this either way."
                    : " The console always recovers this; SSH does too unless the SSH source restriction is also on and excludes you."}
                </span>
              )}
            </div>
            {!w.open && (
              <div className="mt-2 flex flex-wrap gap-1">
                {w.allowed_cidrs.map((c) => (
                  <span
                    key={c}
                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                  >
                    {c}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="shrink-0">
          <button
            type="button"
            onClick={() => setEditing(true)}
            disabled={!!editDisabledReason}
            title={editDisabledReason}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
          >
            Edit…
          </button>
        </div>
      </div>
      {editing && (
        <WebUIAccessModal
          current={w}
          sshDoor={doors?.ssh}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            qc.invalidateQueries({ queryKey: ["firewall", "web-ui-access"] });
            // The door report is derived from BOTH settings, so a Web UI
            // change makes it stale on the SSH screen too.
            qc.invalidateQueries({ queryKey: ["appliance", "remote-access"] });
          }}
        />
      )}
    </div>
  );
}

function parseCidrLines(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function WebUIAccessModal({
  current,
  sshDoor,
  onClose,
  onSaved,
}: {
  current: FirewallWebUIAccess;
  /** #1013 — the other door; undefined if the report could not be read. */
  sshDoor: RemoteDoor | undefined;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [text, setText] = useState(current.allowed_cidrs.join("\n"));
  const [override, setOverride] = useState(false);
  const [ackConsoleOnly, setAckConsoleOnly] = useState(false);
  const save = useMutation({
    mutationFn: () =>
      firewallApi.setWebUIAccess({
        allowed_cidrs: parseCidrLines(text),
        override_lockout: override,
        acknowledge_console_only: ackConsoleOnly,
      }),
    onSuccess: onSaved,
  });
  const cidrs = parseCidrLines(text);
  const errText = save.isError ? formatApiError(save.error) : "";
  // Each 422 is routed on the ACKNOWLEDGEMENT FIELD it names, not on its
  // prose: the field name is the API contract and the sentence around it is
  // not. Reveal each tick only when the server has asked for it, so the
  // operator makes an explicit choice rather than pre-arming one.
  const consoleOnlyError = errText.includes("acknowledge_console_only");
  const lockoutError =
    !consoleOnlyError && errText.includes("override_lockout");
  const sshExcludesMe = Boolean(sshDoor?.restricted && !sshDoor.admits);
  /** Both ticks, and the refusal that asked for them, belong to one list. */
  const resetAcknowledgements = () => {
    setOverride(false);
    setAckConsoleOnly(false);
    save.reset();
  };
  const addMyIp = () => {
    if (!current.caller_ip) return;
    const entry =
      current.caller_ip + (current.caller_ip.includes(":") ? "/128" : "/32");
    setText((t) => (t.trim() ? `${t.trim()}\n${entry}` : entry));
    resetAcknowledgements();
  };
  return (
    <Modal title="Web UI source restriction" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">
          One CIDR (or bare IP) per line — IPv4 and IPv6 both accepted. Leave
          empty to open the Web UI to everyone. This governs both the per-node
          HTTP/HTTPS door (nftables) and the control-plane VIP
          (loadBalancerSourceRanges). A mistake here is always recoverable from
          the console, and over SSH unless the SSH source restriction (Appliance
          → Fleet → SSH) also excludes you.
        </p>
        {/* #1013 — the other door, at the point of decision. */}
        {sshExcludesMe && (
          <p className="rounded-md border border-rose-500/40 bg-rose-500/5 p-2 text-xs">
            <span className="font-medium">SSH is also source-restricted</span> —
            to <code>{sshDoor?.allowed_cidrs.join(", ")}</code>, which does not
            cover <code>{current.caller_ip ?? "your address"}</code>. A list
            here that excludes that address as well leaves the appliance console
            as the only way in, unless you can reach one of those networks
            another way.
          </p>
        )}
        <label className="block">
          <span className="text-xs text-muted-foreground">
            Allowed source ranges
          </span>
          <textarea
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              // #1013 — an acknowledgement belongs to the list that earned
              // it. Left latched, an operator could accept the escalation
              // for list A, retype list B, and save it past a guard the
              // server never got to evaluate. Clearing the error with them
              // returns the modal to a clean state so the next Save is
              // judged on what is actually in the box.
              resetAcknowledgements();
            }}
            rows={5}
            placeholder={"192.168.0.0/24\n10.0.0.0/8\n2001:db8::/64"}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={addMyIp}
            disabled={!current.caller_ip}
            className="rounded-md border px-2.5 py-1 text-xs hover:bg-accent disabled:opacity-50"
          >
            + Add my IP ({current.caller_ip ?? "unknown"})
          </button>
          <button
            type="button"
            onClick={() => {
              setText("");
              resetAcknowledgements();
            }}
            className="rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
          >
            Open to all (clear)
          </button>
        </div>
        {cidrs.length > 0 && (
          <p className="text-xs text-muted-foreground">
            Will restrict the Web UI to {cidrs.length} range
            {cidrs.length === 1 ? "" : "s"}.
          </p>
        )}
        {lockoutError && (
          <label className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-2 text-xs">
            <input
              type="checkbox"
              checked={override}
              onChange={(e) => setOverride(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              Your current source IP isn&rsquo;t covered by this list &mdash;
              saving would cut off this session&rsquo;s path to the Web UI. Tick
              to apply anyway; the SSH allow-list does not exclude this address,
              and the appliance console recovers it either way.
            </span>
          </label>
        )}
        {/* The escalation gets its own tick rather than a sterner sentence in
            the one above: what is being accepted is a larger thing, and the
            server will not take the smaller acknowledgement for it. */}
        {consoleOnlyError && (
          <label className="flex items-start gap-2 rounded-md border border-rose-500/50 bg-rose-500/10 p-2 text-xs">
            <input
              type="checkbox"
              checked={ackConsoleOnly}
              onChange={(e) => setAckConsoleOnly(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium">
                This closes the last remote way in.
              </span>{" "}
              Neither this list nor the SSH allow-list would admit your address,
              so the appliance console becomes the only way to reach this fleet
              &mdash; and a VM with no console attached would need a rebuild.
              Tick to apply anyway.
            </span>
          </label>
        )}
        {save.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(save.error)}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={
              save.isPending ||
              (lockoutError && !override) ||
              (consoleOnlyError && !ackConsoleOnly)
            }
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Save
          </button>
        </div>
      </div>
    </Modal>
  );
}

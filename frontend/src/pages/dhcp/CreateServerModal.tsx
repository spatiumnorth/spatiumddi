import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  dhcpApi,
  type DHCPServer,
  type WindowsDHCPCredentials,
  type FortiGateCredentials,
  formatApiError,
} from "@/lib/api";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";

export function CreateServerModal({
  server,
  defaultGroupId,
  onClose,
}: {
  server?: DHCPServer;
  defaultGroupId?: string | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!server;
  const [name, setName] = useState(server?.name ?? "");
  const [driver, setDriver] = useState(server?.driver ?? "kea");
  const [host, setHost] = useState(server?.host ?? "");
  const [port, setPort] = useState(String(server?.port ?? 67));
  const [groupId, setGroupId] = useState<string>(
    server?.server_group_id ?? defaultGroupId ?? "",
  );
  const [haPeerUrl, setHaPeerUrl] = useState<string>(server?.ha_peer_url ?? "");
  const [description, setDescription] = useState(server?.description ?? "");
  const [error, setError] = useState("");

  // Windows-only fields. When editing a server that already has creds set,
  // we leave the fields blank and only submit them if the user types a new
  // password — matches the "None → leave alone, {} → clear" server contract.
  const [winUsername, setWinUsername] = useState("");
  const [winPassword, setWinPassword] = useState("");
  const [winPort, setWinPort] = useState("5985");
  const [winTransport, setWinTransport] =
    useState<WindowsDHCPCredentials["transport"]>("ntlm");
  const [winUseTLS, setWinUseTLS] = useState(false);
  const [winVerifyTLS, setWinVerifyTLS] = useState(false);
  const [winClearCreds, setWinClearCreds] = useState(false);

  // FortiGate-only fields. Same "blank = keep stored" contract on edit.
  const [fgToken, setFgToken] = useState("");
  const [fgVdom, setFgVdom] = useState(server?.vdom ?? "root");
  // Seed from the stored value so an unrelated edit doesn't silently re-disable
  // verification. Secure default (true) for new servers and legacy rows the API
  // can't echo. See H2 in PR #630 review.
  const [fgVerifyTLS, setFgVerifyTLS] = useState(server?.verify_tls ?? true);
  // Optional private-CA PEM. Write-only (blank = keep stored), like the token.
  const [fgCaBundle, setFgCaBundle] = useState("");
  const [fgClearCreds, setFgClearCreds] = useState(false);

  const [testResult, setTestResult] = useState<{
    ok: boolean;
    message: string;
  } | null>(null);

  const hasExistingCreds = !!server?.has_credentials;

  const testMut = useMutation({
    mutationFn: () => {
      // Two modes — mirrors the backend endpoints:
      //  * Plaintext form values (pre-save probe before the user hits Save).
      //  * server_id-only (use stored Fernet-encrypted creds; only makes
      //    sense when editing a server that already has creds and the
      //    user hasn't typed new ones).
      if (driver === "fortigate") {
        const useStored = editing && hasExistingCreds && !fgToken;
        if (useStored) {
          return dhcpApi.testFortigateCredentials({
            host,
            port: parseInt(port, 10) || 443,
            server_id: server!.id,
          });
        }
        return dhcpApi.testFortigateCredentials({
          host,
          port: parseInt(port, 10) || 443,
          credentials: {
            api_token: fgToken,
            vdom: fgVdom || "root",
            verify_tls: fgVerifyTLS,
            ...(fgCaBundle.trim() ? { ca_bundle_pem: fgCaBundle.trim() } : {}),
          },
        });
      }
      const useStored =
        editing && hasExistingCreds && !winPassword && !winUsername;
      if (useStored) {
        return dhcpApi.testWindowsCredentials({
          host,
          server_id: server!.id,
        });
      }
      return dhcpApi.testWindowsCredentials({
        host,
        credentials: {
          username: winUsername,
          password: winPassword,
          winrm_port: parseInt(winPort, 10) || 5985,
          transport: winTransport,
          use_tls: winUseTLS,
          verify_tls: winVerifyTLS,
        },
      });
    },
    onSuccess: setTestResult,
    onError: (e) =>
      setTestResult({ ok: false, message: errMsg(e, "Test failed") }),
  });

  const { data: groups = [] } = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
  });

  const mut = useMutation({
    mutationFn: () => {
      const data: Partial<DHCPServer> & {
        windows_credentials?: WindowsDHCPCredentials | Record<string, never>;
        cloud_credentials?: FortiGateCredentials | Record<string, never>;
        ha_peer_url?: string;
      } = {
        name,
        driver,
        host,
        port:
          parseInt(port, 10) ||
          (driver === "windows_dhcp" ? 0 : driver === "fortigate" ? 443 : 67),
        server_group_id: groupId || null,
        ha_peer_url: haPeerUrl,
        description,
      };

      if (driver === "fortigate") {
        if (fgClearCreds) {
          data.cloud_credentials = {};
        } else {
          const creds: FortiGateCredentials = {
            vdom: fgVdom || "root",
            verify_tls: fgVerifyTLS,
          };
          if (fgToken) creds.api_token = fgToken;
          if (fgCaBundle.trim()) creds.ca_bundle_pem = fgCaBundle.trim();
          if (!editing && !fgToken) {
            throw new Error(
              "FortiGate requires an API token to connect over the REST API.",
            );
          }
          data.cloud_credentials = creds;
        }
      }

      if (driver === "windows_dhcp") {
        if (winClearCreds) {
          data.windows_credentials = {};
        } else {
          // Always send the creds block on windows_dhcp so transport / port /
          // TLS toggles reach the backend even when username+password are
          // blank (edit case — backend merges with stored blob). The backend
          // requires username+password only on first-time set.
          const creds: Partial<WindowsDHCPCredentials> = {
            winrm_port: parseInt(winPort, 10) || 5985,
            transport: winTransport,
            use_tls: winUseTLS,
            verify_tls: winVerifyTLS,
          };
          if (winUsername) creds.username = winUsername;
          if (winPassword) creds.password = winPassword;
          if (!editing && (!winUsername || !winPassword)) {
            throw new Error(
              "Windows DHCP requires a username + password to connect over WinRM.",
            );
          }
          data.windows_credentials = creds as WindowsDHCPCredentials;
        }
      }

      return editing
        ? dhcpApi.updateServer(server!.id, data)
        : dhcpApi.createServer(data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-servers"] });
      qc.invalidateQueries({ queryKey: ["dhcp-groups"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save server")),
  });

  const isWindows = driver === "windows_dhcp";
  const isFortigate = driver === "fortigate";

  return (
    <Modal
      title={editing ? "Edit DHCP Server" : "New DHCP Server"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError("");
          try {
            mut.mutate();
          } catch (err) {
            setError(formatApiError(err));
          }
        }}
        className="space-y-3"
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </Field>
          <Field label="Driver">
            <select
              className={inputCls}
              value={driver}
              onChange={(e) => {
                const next = e.target.value;
                setDriver(next);
                // Helpful default: DHCP native port is irrelevant for WinRM,
                // FortiGate uses its HTTPS admin port (443), Kea/ISC need 67.
                if (next === "windows_dhcp") {
                  setPort("0");
                } else if (next === "fortigate") {
                  setPort("443");
                } else if (port === "0" || port === "443") {
                  setPort("67");
                }
              }}
            >
              <option value="kea">Kea</option>
              <option value="windows_dhcp">
                Windows DHCP (WinRM, read-only)
              </option>
              <optgroup label="Agentless (REST API)">
                <option value="fortigate">FortiGate (FortiOS REST)</option>
              </optgroup>
            </select>
          </Field>
          <Field label="Host">
            <input
              className={inputCls}
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder={
                isWindows
                  ? "192.168.0.10 or dc01.corp.example.com"
                  : isFortigate
                    ? "192.168.1.99 or fw01.corp.example.com"
                    : "10.0.0.10"
              }
              required
            />
          </Field>
          <Field
            label={
              isWindows
                ? "DHCP Port (informational)"
                : isFortigate
                  ? "HTTPS Admin Port"
                  : "Port"
            }
          >
            <input
              type="number"
              className={inputCls}
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </Field>
          <Field label="Server Group">
            <select
              className={inputCls}
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
            >
              <option value="">— None —</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
        </div>
        {driver === "kea" && (
          <Field
            label="HA Peer URL (optional)"
            hint="This server's own Kea HA hook listener endpoint. Required for Kea HA pairs — the partner calls this URL for heartbeats and lease updates. Leave blank for standalone servers. Example: http://dhcp-kea:8000/"
          >
            <input
              className={inputCls}
              placeholder="http://dhcp-kea:8000/"
              value={haPeerUrl}
              onChange={(e) => setHaPeerUrl(e.target.value)}
            />
          </Field>
        )}
        <Field label="Description">
          <textarea
            className={inputCls}
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        {isFortigate && (
          <div className="rounded-md border border-sky-500/40 bg-sky-500/5 p-3 space-y-3">
            <div className="text-xs">
              <div className="font-medium text-sky-600 dark:text-sky-400">
                FortiGate — agentless (FortiOS REST API)
              </div>
              <p className="mt-1 text-muted-foreground">
                SpatiumDDI manages this FortiGate's per-interface DHCP over the
                REST API with an API-admin token. Each SpatiumDDI subnet is
                matched to the FortiGate interface with the same CIDR and its
                DHCP server (range, reservations, exclusions, options) is pushed
                on every edit. SpatiumDDI is the source of truth (push-only);
                the token is stored Fernet-encrypted and never returned.
              </p>
            </div>

            <details className="rounded border bg-background/40 text-xs">
              <summary className="cursor-pointer px-3 py-2 font-medium select-none">
                FortiGate setup — click to expand
              </summary>
              <div className="space-y-2 border-t px-3 py-2.5 text-muted-foreground">
                <p>
                  Create a REST API admin with a DHCP-capable profile and copy
                  its token:
                </p>
                <ol className="list-decimal space-y-1 pl-5">
                  <li>
                    System → Administrators → Create New → REST API Admin.
                  </li>
                  <li>
                    Give it an Administrator profile with read-write on{" "}
                    <code className="font-mono">System</code> (DHCP lives under
                    system.dhcp) for the target VDOM.
                  </li>
                  <li>
                    Restrict the Trusted Hosts to the SpatiumDDI control-plane
                    IP.
                  </li>
                  <li>Copy the generated API token into the field below.</li>
                </ol>
                <p>
                  The interface that serves each subnet must already have its
                  IP/netmask configured — SpatiumDDI matches on CIDR and never
                  changes interface addressing.
                </p>
              </div>
            </details>

            {hasExistingCreds && !fgClearCreds && (
              <div className="flex items-center justify-between rounded border bg-background/50 px-3 py-2 text-xs">
                <span>
                  <span className="font-medium">API token set.</span> Leave the
                  token blank to keep it, or enter a new one to replace.
                </span>
                <button
                  type="button"
                  onClick={() => setFgClearCreds(true)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Clear
                </button>
              </div>
            )}
            {fgClearCreds && (
              <div className="flex items-center justify-between rounded border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs">
                <span className="text-destructive">
                  Credentials will be removed on save.
                </span>
                <button
                  type="button"
                  onClick={() => setFgClearCreds(false)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Undo
                </button>
              </div>
            )}

            <div
              className={`grid grid-cols-2 gap-3 ${fgClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              <Field label="API Token" hint="FortiOS REST API admin token">
                <input
                  type="password"
                  className={inputCls}
                  value={fgToken}
                  onChange={(e) => setFgToken(e.target.value)}
                  placeholder={hasExistingCreds ? "(unchanged)" : "required"}
                  autoComplete="off"
                />
              </Field>
              <Field label="VDOM" hint="Virtual domain (default: root)">
                <input
                  className={inputCls}
                  value={fgVdom}
                  onChange={(e) => setFgVdom(e.target.value)}
                  placeholder="root"
                />
              </Field>
              <Field label="Verify TLS certificate">
                <input
                  type="checkbox"
                  checked={fgVerifyTLS}
                  onChange={(e) => setFgVerifyTLS(e.target.checked)}
                />
              </Field>
              <Field
                label="CA bundle (PEM)"
                hint="Optional — pin a private-CA FortiGate without disabling verification"
              >
                <textarea
                  className={`${inputCls} font-mono text-xs`}
                  rows={3}
                  value={fgCaBundle}
                  onChange={(e) => setFgCaBundle(e.target.value)}
                  placeholder={
                    hasExistingCreds
                      ? "(unchanged — leave blank to keep stored)"
                      : "-----BEGIN CERTIFICATE-----"
                  }
                  autoComplete="off"
                />
              </Field>
            </div>

            <div
              className={`flex items-center gap-3 ${fgClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              <button
                type="button"
                onClick={() => {
                  setTestResult(null);
                  testMut.mutate();
                }}
                disabled={
                  testMut.isPending ||
                  !host ||
                  (!fgToken && !(editing && hasExistingCreds))
                }
                className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
              >
                {testMut.isPending ? "Testing…" : "Test Connection"}
              </button>
              {editing && hasExistingCreds && !fgToken && (
                <span className="text-[11px] text-muted-foreground">
                  will use stored token
                </span>
              )}
              {testResult && (
                <span
                  className={`text-xs ${testResult.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}
                >
                  {testResult.ok ? "✓ " : "✗ "}
                  {testResult.message}
                </span>
              )}
            </div>
          </div>
        )}

        {isWindows && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 space-y-3">
            <div className="text-xs">
              <div className="font-medium text-amber-600 dark:text-amber-400">
                Windows DHCP — read-only (Path A)
              </div>
              <p className="mt-1 text-muted-foreground">
                SpatiumDDI polls the DHCP server over WinRM and imports active
                leases into DHCP + IPAM. Config management (scopes,
                reservations) stays in Windows Server. Enable the schedule in{" "}
                <span className="font-medium">Settings → DHCP Lease Sync</span>{" "}
                or click <span className="font-medium">Sync Leases</span> on the
                server page for a one-shot. Credentials are stored Fernet-
                encrypted and never returned by the API.
              </p>
            </div>

            <details className="rounded border bg-background/40 text-xs">
              <summary className="cursor-pointer px-3 py-2 font-medium select-none">
                Windows setup checklist — click to expand
              </summary>
              <div className="space-y-3 border-t px-3 py-2.5 text-muted-foreground">
                <div>
                  <div className="font-medium text-foreground">
                    1. Enable WinRM on the DHCP server
                  </div>
                  <p>In an elevated PowerShell on the DHCP host:</p>
                  <pre className="mt-1 rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    Enable-PSRemoting -Force{"\n"}
                    {
                      "# opens firewall, starts WinRM, listens on 5985 (HTTP) by default"
                    }
                  </pre>
                </div>

                <div>
                  <div className="font-medium text-foreground">
                    2. Create a service account (AD or local)
                  </div>
                  <p>
                    Keep it purpose-built and scoped. Disable interactive logon
                    if possible.
                  </p>
                </div>

                <div>
                  <div className="font-medium text-foreground">
                    3. Grant WinRM access
                  </div>
                  <p>
                    Add the service account to the{" "}
                    <code className="font-mono">Remote Management Users</code>{" "}
                    local group on the DHCP host — "DHCP Users" alone is{" "}
                    <em>not</em> enough; that's PowerShell-level authorization,
                    not transport-level:
                  </p>
                  <pre className="mt-1 rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    Add-LocalGroupMember -Group "Remote Management Users"
                    {" -Member 'CORP\\dhcpreader'"}
                  </pre>
                </div>

                <div>
                  <div className="font-medium text-foreground">
                    4. Grant DHCP read rights
                  </div>
                  <p>
                    Add the same account to the{" "}
                    <code className="font-mono">DHCP Users</code> built-in group
                    (read-only) — or{" "}
                    <code className="font-mono">DHCP Administrators</code> if
                    you plan to use Path B (full CRUD) later:
                  </p>
                  <pre className="mt-1 rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    Add-LocalGroupMember -Group "DHCP Users"
                    {" -Member 'CORP\\dhcpreader'"}
                  </pre>
                </div>

                <div>
                  <div className="font-medium text-foreground">
                    5. (Optional) HTTPS listener
                  </div>
                  <p>
                    If you toggle "Use HTTPS" below, set up a 5986 listener
                    bound to a cert that matches the host you entered above:
                  </p>
                  <pre className="mt-1 rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    {
                      "winrm quickconfig -transport:https\n# or bind an explicit cert:\nNew-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * -CertificateThumbprint <thumb>"
                    }
                  </pre>
                </div>

                <div>
                  <div className="font-medium text-foreground">
                    6. Verify from another host
                  </div>
                  <pre className="rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    {
                      "Test-WSMan -ComputerName <host>\nInvoke-Command <host> { Get-DhcpServerVersion } -Credential (Get-Credential)"
                    }
                  </pre>
                </div>

                <div className="rounded border border-amber-500/30 bg-amber-500/5 p-2.5">
                  <div className="font-medium text-amber-700 dark:text-amber-400">
                    Extra step on Domain Controllers
                  </div>
                  <p className="mt-1">
                    DCs don't have local groups — everything is AD — and the
                    Default Domain Controllers Policy (DDCP) only grants
                    user-rights privileges to{" "}
                    <code className="font-mono">Administrators</code>. If WinRM
                    accepts your service account but then fails with{" "}
                    <code className="font-mono">
                      0x80080005 CO_E_SERVER_EXEC_FAILURE
                    </code>{" "}
                    (the "wsman could not launch a host process" error), the
                    account is missing one of these process-creation rights.
                    Edit DDCP in <code>gpmc.msc</code> → Computer Config →
                    Policies → Windows Settings → Security Settings → Local
                    Policies → User Rights Assignment, and add the service
                    account (or the <code>Remote Management Users</code> group)
                    to <strong>all</strong> of:
                  </p>
                  <ul className="mt-1.5 list-disc pl-5 text-[11px]">
                    <li>
                      <span className="font-mono">Log on as a batch job</span>{" "}
                      (SeBatchLogonRight)
                    </li>
                    <li>
                      <span className="font-mono">
                        Replace a process level token
                      </span>{" "}
                      (SeAssignPrimaryTokenPrivilege)
                    </li>
                    <li>
                      <span className="font-mono">
                        Adjust memory quotas for a process
                      </span>{" "}
                      (SeIncreaseQuotaPrivilege)
                    </li>
                    <li>
                      <span className="font-mono">
                        Impersonate a client after authentication
                      </span>{" "}
                      (SeImpersonatePrivilege) — usually already granted, add if
                      not
                    </li>
                  </ul>
                  <p className="mt-1.5">
                    Then <code>gpupdate /force</code> on the DC and{" "}
                    <code>Restart-Service WinRM</code>. A non-admin service
                    account on a DC needs all four to spawn{" "}
                    <code className="font-mono">wsmprovhost.exe</code> under its
                    token. On a member server the same role usually works with
                    just step 3 + 4 above because the local policy grants the
                    process rights by default.
                  </p>
                </div>
              </div>
            </details>

            {hasExistingCreds && !winClearCreds && (
              <div className="flex items-center justify-between rounded border bg-background/50 px-3 py-2 text-xs">
                <span>
                  <span className="font-medium">Credentials set.</span> Leave
                  fields blank to keep them, or enter new values to replace.
                </span>
                <button
                  type="button"
                  onClick={() => setWinClearCreds(true)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Clear
                </button>
              </div>
            )}
            {winClearCreds && (
              <div className="flex items-center justify-between rounded border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs">
                <span className="text-destructive">
                  Credentials will be removed on save.
                </span>
                <button
                  type="button"
                  onClick={() => setWinClearCreds(false)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Undo
                </button>
              </div>
            )}

            <div
              className={`grid grid-cols-2 gap-3 ${winClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              <Field
                label="Username"
                hint={
                  "CORP\\user   or   user@corp.local   or bare 'user' for a local account"
                }
              >
                <input
                  className={inputCls}
                  value={winUsername}
                  onChange={(e) => setWinUsername(e.target.value)}
                  placeholder={"CORP\\dhcpreader"}
                  autoComplete="off"
                />
              </Field>
              <Field label="Password">
                <input
                  type="password"
                  className={inputCls}
                  value={winPassword}
                  onChange={(e) => setWinPassword(e.target.value)}
                  placeholder={hasExistingCreds ? "(unchanged)" : "required"}
                  autoComplete="off"
                />
              </Field>
              <Field label="WinRM Port">
                <input
                  type="number"
                  className={inputCls}
                  value={winPort}
                  onChange={(e) => setWinPort(e.target.value)}
                />
              </Field>
              <Field label="Auth Transport">
                <select
                  className={inputCls}
                  value={winTransport}
                  onChange={(e) =>
                    setWinTransport(
                      e.target.value as WindowsDHCPCredentials["transport"],
                    )
                  }
                >
                  <option value="ntlm">NTLM</option>
                  <option value="basic">Basic</option>
                  <option value="credssp">CredSSP</option>
                </select>
              </Field>
              <Field label="Use HTTPS (port 5986)">
                <input
                  type="checkbox"
                  checked={winUseTLS}
                  onChange={(e) => {
                    setWinUseTLS(e.target.checked);
                    if (e.target.checked && winPort === "5985")
                      setWinPort("5986");
                    if (!e.target.checked && winPort === "5986")
                      setWinPort("5985");
                  }}
                />
              </Field>
              <Field label="Verify TLS certificate">
                <input
                  type="checkbox"
                  checked={winVerifyTLS}
                  disabled={!winUseTLS}
                  onChange={(e) => setWinVerifyTLS(e.target.checked)}
                />
              </Field>
            </div>

            <div
              className={`flex items-center gap-3 ${winClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              <button
                type="button"
                onClick={() => {
                  setTestResult(null);
                  testMut.mutate();
                }}
                disabled={
                  testMut.isPending ||
                  !host ||
                  // Either the form has fresh creds, or we'll fall through
                  // to server_id (which only exists for an already-saved
                  // server with has_credentials=true).
                  (!winUsername &&
                    !(editing && hasExistingCreds && !winPassword))
                }
                className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
              >
                {testMut.isPending ? "Testing…" : "Test Connection"}
              </button>
              {editing && hasExistingCreds && !winUsername && !winPassword && (
                <span className="text-[11px] text-muted-foreground">
                  will use stored credentials
                </span>
              )}
              {testResult && (
                <span
                  className={`text-xs ${testResult.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}
                >
                  {testResult.ok ? "✓ " : "✗ "}
                  {testResult.message}
                </span>
              )}
            </div>
          </div>
        )}

        {error && <p className="text-xs text-destructive">{error}</p>}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}

export const EditServerModal = CreateServerModal;

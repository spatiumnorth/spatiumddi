import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  TestTube2,
  XCircle,
} from "lucide-react";

import {
  networkApi,
  type NetworkDeviceCreate,
  type NetworkDeviceRead,
  type NetworkDeviceType,
  type NetworkDeviceUpdate,
  type NetworkSnmpVersion,
  type NetworkTestConnectionResult,
  type NetworkV3AuthProtocol,
  type NetworkV3PrivProtocol,
  type NetworkV3SecurityLevel,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";

import { DEVICE_SECONDS_BOUNDS, secondsFieldError } from "@/lib/seconds";
import { DEVICE_TYPE_OPTIONS, Field, errMsg, inputCls } from "./_shared";

// ── Static option lists ──────────────────────────────────────────────

const V3_AUTH_PROTOCOLS: NetworkV3AuthProtocol[] = [
  "MD5",
  "SHA",
  "SHA224",
  "SHA256",
  "SHA384",
  "SHA512",
];
const V3_PRIV_PROTOCOLS: NetworkV3PrivProtocol[] = [
  "DES",
  "3DES",
  "AES128",
  "AES192",
  "AES256",
];

// ── Modal ────────────────────────────────────────────────────────────

// Single component used for create + edit. Mirrors the EditSubnetModal /
// CreateSubnetModal consolidation pattern we already have elsewhere.
//
// On edit, the read schema returns ``has_community`` / ``has_auth_key`` /
// ``has_priv_key`` boolean flags (never the secret itself). When they're
// true we leave the corresponding input blank and use a placeholder so
// the operator can either clear the value or paste a new one — leaving
// it untouched keeps whatever the backend already has stored.
export function DeviceFormModal({
  device,
  onClose,
}: {
  device?: NetworkDeviceRead;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!device;

  // Identity
  const [name, setName] = useState(device?.name ?? "");
  const [hostname, setHostname] = useState(device?.hostname ?? "");
  const [ipAddress, setIpAddress] = useState(device?.ip_address ?? "");
  const [deviceType, setDeviceType] = useState<NetworkDeviceType>(
    device?.device_type ?? "switch",
  );
  const [description, setDescription] = useState(device?.description ?? "");

  // IP space
  const [ipSpaceId, setIpSpaceId] = useState(device?.ip_space_id ?? "");

  // SNMP transport
  const [snmpVersion, setSnmpVersion] = useState<NetworkSnmpVersion>(
    device?.snmp_version ?? "v2c",
  );
  const [snmpPort, setSnmpPort] = useState(device?.snmp_port ?? 161);
  const [snmpTimeout, setSnmpTimeout] = useState(
    String(device?.snmp_timeout_seconds ?? 5),
  );
  const [snmpRetries, setSnmpRetries] = useState(device?.snmp_retries ?? 1);

  // v1/v2c credentials. Pre-fill ``public`` on create so the most
  // common default is one click away — operator just hits Save. On
  // edit we leave it blank so the placeholder ("(unchanged …)")
  // explains the rotate-or-keep semantics.
  const [community, setCommunity] = useState(editing ? "" : "public");

  // v3 credentials
  const [v3SecurityName, setV3SecurityName] = useState(
    device?.v3_security_name ?? "",
  );
  const [v3SecurityLevel, setV3SecurityLevel] =
    useState<NetworkV3SecurityLevel>(device?.v3_security_level ?? "authPriv");
  const [v3AuthProtocol, setV3AuthProtocol] = useState<NetworkV3AuthProtocol>(
    device?.v3_auth_protocol ?? "SHA",
  );
  const [v3AuthKey, setV3AuthKey] = useState("");
  const [v3PrivProtocol, setV3PrivProtocol] = useState<NetworkV3PrivProtocol>(
    device?.v3_priv_protocol ?? "AES128",
  );
  const [v3PrivKey, setV3PrivKey] = useState("");
  const [v3ContextName, setV3ContextName] = useState(
    device?.v3_context_name ?? "",
  );

  // Polling
  const [pollInterval, setPollInterval] = useState(
    String(device?.poll_interval_seconds ?? 300),
  );
  const [pollArp, setPollArp] = useState(device?.poll_arp ?? true);
  const [pollFdb, setPollFdb] = useState(device?.poll_fdb ?? true);
  const [pollInterfaces, setPollInterfaces] = useState(
    device?.poll_interfaces ?? true,
  );
  const [pollLldp, setPollLldp] = useState(device?.poll_lldp ?? true);
  const [autoCreate, setAutoCreate] = useState(
    device?.auto_create_discovered ?? false,
  );

  // Activity
  const [isActive, setIsActive] = useState(device?.is_active ?? true);

  // Errors + test results
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] =
    useState<NetworkTestConnectionResult | null>(null);

  // ── Validation helpers ──

  function validate(): string | null {
    if (!name.trim()) return "Name is required";
    if (!ipAddress.trim()) return "IP address is required";
    if (!ipSpaceId) return "IP space is required";
    if (snmpVersion === "v1" || snmpVersion === "v2c") {
      // On create the community must be set; on edit, leaving it blank
      // means "keep the current value" so we only require it if there
      // isn't one stored already.
      if (!editing && !community.trim()) {
        return "Community string is required for SNMP v1/v2c";
      }
      if (editing && !device?.has_community && !community.trim()) {
        return "Community string is required for SNMP v1/v2c";
      }
    } else {
      // v3
      if (!v3SecurityName.trim()) return "SNMP v3 security name is required";
      if (v3SecurityLevel === "authNoPriv" || v3SecurityLevel === "authPriv") {
        if (!editing && !v3AuthKey.trim())
          return "Auth key is required for authNoPriv / authPriv";
        if (editing && !device?.has_auth_key && !v3AuthKey.trim())
          return "Auth key is required for authNoPriv / authPriv";
      }
      if (v3SecurityLevel === "authPriv") {
        if (!editing && !v3PrivKey.trim())
          return "Privacy key is required for authPriv";
        if (editing && !device?.has_priv_key && !v3PrivKey.trim())
          return "Privacy key is required for authPriv";
      }
    }
    // #2110 — "1h" and an empty field are refused, never read as 1 / the default.
    return (
      secondsFieldError("SNMP timeout", snmpTimeout, DEVICE_SECONDS_BOUNDS) ??
      secondsFieldError("Poll interval", pollInterval, DEVICE_SECONDS_BOUNDS)
    );
  }

  // ── Build payload ──

  function buildCreatePayload(): NetworkDeviceCreate {
    const body: NetworkDeviceCreate = {
      name: name.trim(),
      hostname: hostname.trim(),
      ip_address: ipAddress.trim(),
      device_type: deviceType,
      description: description || null,
      snmp_version: snmpVersion,
      snmp_port: snmpPort,
      snmp_timeout_seconds: Number(snmpTimeout.trim()),
      snmp_retries: snmpRetries,
      poll_interval_seconds: Number(pollInterval.trim()),
      poll_arp: pollArp,
      poll_fdb: pollFdb,
      poll_interfaces: pollInterfaces,
      poll_lldp: pollLldp,
      auto_create_discovered: autoCreate,
      ip_space_id: ipSpaceId,
      is_active: isActive,
    };
    if (snmpVersion === "v1" || snmpVersion === "v2c") {
      if (community) body.community = community;
    } else {
      body.v3_security_name = v3SecurityName.trim();
      body.v3_security_level = v3SecurityLevel;
      if (v3SecurityLevel !== "noAuthNoPriv") {
        body.v3_auth_protocol = v3AuthProtocol;
        if (v3AuthKey) body.v3_auth_key = v3AuthKey;
      }
      if (v3SecurityLevel === "authPriv") {
        body.v3_priv_protocol = v3PrivProtocol;
        if (v3PrivKey) body.v3_priv_key = v3PrivKey;
      }
      if (v3ContextName) body.v3_context_name = v3ContextName;
    }
    return body;
  }

  function buildUpdatePayload(): NetworkDeviceUpdate {
    // Update is the same shape minus the ip_space_id required-ness.
    // Empty secrets are dropped server-side per spec ("leave blank to
    // keep existing").
    const body: NetworkDeviceUpdate = {
      name: name.trim(),
      hostname: hostname.trim(),
      ip_address: ipAddress.trim(),
      device_type: deviceType,
      description: description || null,
      snmp_version: snmpVersion,
      snmp_port: snmpPort,
      snmp_timeout_seconds: Number(snmpTimeout.trim()),
      snmp_retries: snmpRetries,
      poll_interval_seconds: Number(pollInterval.trim()),
      poll_arp: pollArp,
      poll_fdb: pollFdb,
      poll_interfaces: pollInterfaces,
      poll_lldp: pollLldp,
      auto_create_discovered: autoCreate,
      ip_space_id: ipSpaceId,
      is_active: isActive,
    };
    if (snmpVersion === "v1" || snmpVersion === "v2c") {
      if (community) body.community = community;
    } else {
      body.v3_security_name = v3SecurityName.trim();
      body.v3_security_level = v3SecurityLevel;
      if (v3SecurityLevel !== "noAuthNoPriv") {
        body.v3_auth_protocol = v3AuthProtocol;
        if (v3AuthKey) body.v3_auth_key = v3AuthKey;
      }
      if (v3SecurityLevel === "authPriv") {
        body.v3_priv_protocol = v3PrivProtocol;
        if (v3PrivKey) body.v3_priv_key = v3PrivKey;
      }
      body.v3_context_name = v3ContextName;
    }
    return body;
  }

  // ── Mutations ──

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        return networkApi.updateDevice(device!.id, buildUpdatePayload());
      }
      return networkApi.createDevice(buildCreatePayload());
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["network-devices"] });
      qc.invalidateQueries({ queryKey: ["network-device", device?.id] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save device")),
  });

  // Test only works on a saved device — the backend reads the stored
  // (encrypted) credentials by ID. On create we save first; the
  // ConfirmModal below gates that path so a fat-fingered click on a
  // brand-new form doesn't quietly create a stray device row.
  const [showTestConfirm, setShowTestConfirm] = useState(false);
  const testMut = useMutation({
    mutationFn: async (): Promise<NetworkTestConnectionResult> => {
      let id = device?.id;
      if (!id) {
        const created = await networkApi.createDevice(buildCreatePayload());
        id = created.id;
        qc.invalidateQueries({ queryKey: ["network-devices"] });
      }
      return networkApi.testConnection(id);
    },
    onSuccess: (result) => {
      setTestResult(result);
      qc.invalidateQueries({ queryKey: ["network-devices"] });
      qc.invalidateQueries({ queryKey: ["network-device", device?.id] });
    },
    onError: (e) => {
      const message = errMsg(e, "Test failed");
      setTestResult({
        success: false,
        sys_descr: null,
        sys_object_id: null,
        sys_name: null,
        vendor: null,
        error_kind: "internal",
        error_message: message,
        elapsed_ms: 0,
      });
    },
  });

  // ── Render ──

  return (
    <Modal
      title={editing ? `Edit ${device!.name}` : "Add Network Device"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const v = validate();
          if (v) {
            setError(v);
            return;
          }
          setError(null);
          saveMut.mutate();
        }}
        className="space-y-3"
      >
        {/* Identity */}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
              placeholder="core-sw-01"
            />
          </Field>
          <Field label="Type">
            <select
              className={inputCls}
              value={deviceType}
              onChange={(e) =>
                setDeviceType(e.target.value as NetworkDeviceType)
              }
            >
              {DEVICE_TYPE_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="IP address" hint="Used for SNMP transport. Required.">
            <input
              className={`${inputCls} font-mono text-[12px]`}
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              required
              placeholder="10.0.0.1"
            />
          </Field>
          <Field label="Hostname (optional)" hint="FQDN — display only.">
            <input
              className={inputCls}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="core-sw-01.lab.example.com"
            />
          </Field>
        </div>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional"
          />
        </Field>

        {/* IP Space binding */}
        <Field
          label="IP space"
          hint="Discovered IPs land in this space when auto-create is on."
        >
          <IPSpacePicker value={ipSpaceId} onChange={setIpSpaceId} required />
        </Field>

        {/* SNMP transport */}
        <div className="rounded-md border bg-muted/30 p-3 space-y-3">
          <h3 className="text-sm font-semibold">SNMP transport</h3>
          <div className="grid grid-cols-3 gap-3">
            <Field label="Version">
              <div className="flex gap-1">
                {(["v1", "v2c", "v3"] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setSnmpVersion(v)}
                    className={`flex-1 rounded-md border px-2 py-1.5 text-sm uppercase ${
                      snmpVersion === v
                        ? "bg-primary text-primary-foreground"
                        : "hover:bg-muted"
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </Field>
            <Field label="Port">
              <input
                type="number"
                className={inputCls}
                value={snmpPort}
                min={1}
                max={65535}
                onChange={(e) => setSnmpPort(parseInt(e.target.value) || 161)}
              />
            </Field>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Timeout (s)">
                <input
                  type="number"
                  className={inputCls}
                  value={snmpTimeout}
                  min={1}
                  max={60}
                  onChange={(e) => setSnmpTimeout(e.target.value)}
                />
              </Field>
              <Field label="Retries">
                <input
                  type="number"
                  className={inputCls}
                  value={snmpRetries}
                  min={0}
                  max={10}
                  onChange={(e) =>
                    setSnmpRetries(parseInt(e.target.value) || 0)
                  }
                />
              </Field>
            </div>
          </div>

          {/* Credentials. SNMP v1/v2c community travels in cleartext on
              the wire; treating it as a "password" in the input field
              just hides the pre-filled default behind dots, which is
              more confusing than helpful. Render as plain text so the
              operator can see the value they're saving. (v3 auth/priv
              keys stay as ``type=password`` below — those ARE secrets.) */}
          {(snmpVersion === "v1" || snmpVersion === "v2c") && (
            <Field
              label="Community string"
              hint="SNMP v1/v2c community. ``public`` is the most common default."
            >
              <input
                type="text"
                className={inputCls}
                value={community}
                onChange={(e) => setCommunity(e.target.value)}
                placeholder={
                  editing && device?.has_community
                    ? "(unchanged — leave blank to keep existing)"
                    : "public"
                }
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
          )}

          {snmpVersion === "v3" && (
            <div className="space-y-3 border-t pt-3">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Security name">
                  <input
                    className={inputCls}
                    value={v3SecurityName}
                    onChange={(e) => setV3SecurityName(e.target.value)}
                    placeholder="snmpv3-readonly"
                  />
                </Field>
                <Field label="Security level">
                  <select
                    className={inputCls}
                    value={v3SecurityLevel}
                    onChange={(e) =>
                      setV3SecurityLevel(
                        e.target.value as NetworkV3SecurityLevel,
                      )
                    }
                  >
                    <option value="noAuthNoPriv">noAuthNoPriv</option>
                    <option value="authNoPriv">authNoPriv</option>
                    <option value="authPriv">authPriv</option>
                  </select>
                </Field>
              </div>
              {(v3SecurityLevel === "authNoPriv" ||
                v3SecurityLevel === "authPriv") && (
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Auth protocol">
                    <select
                      className={inputCls}
                      value={v3AuthProtocol}
                      onChange={(e) =>
                        setV3AuthProtocol(
                          e.target.value as NetworkV3AuthProtocol,
                        )
                      }
                    >
                      {V3_AUTH_PROTOCOLS.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Auth key">
                    <input
                      type="password"
                      className={inputCls}
                      value={v3AuthKey}
                      onChange={(e) => setV3AuthKey(e.target.value)}
                      placeholder={
                        editing && device?.has_auth_key
                          ? "(unchanged — leave blank to keep existing)"
                          : ""
                      }
                      autoComplete="new-password"
                    />
                  </Field>
                </div>
              )}
              {v3SecurityLevel === "authPriv" && (
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Privacy protocol">
                    <select
                      className={inputCls}
                      value={v3PrivProtocol}
                      onChange={(e) =>
                        setV3PrivProtocol(
                          e.target.value as NetworkV3PrivProtocol,
                        )
                      }
                    >
                      {V3_PRIV_PROTOCOLS.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Privacy key">
                    <input
                      type="password"
                      className={inputCls}
                      value={v3PrivKey}
                      onChange={(e) => setV3PrivKey(e.target.value)}
                      placeholder={
                        editing && device?.has_priv_key
                          ? "(unchanged — leave blank to keep existing)"
                          : ""
                      }
                      autoComplete="new-password"
                    />
                  </Field>
                </div>
              )}
              <Field
                label="Context name"
                hint="Optional. Leave blank unless your SNMP v3 deployment uses contexts."
              >
                <input
                  className={inputCls}
                  value={v3ContextName}
                  onChange={(e) => setV3ContextName(e.target.value)}
                />
              </Field>
            </div>
          )}
        </div>

        {/* Polling */}
        <div className="rounded-md border bg-muted/30 p-3 space-y-3">
          <h3 className="text-sm font-semibold">Polling</h3>
          <Field
            label="Interval (seconds)"
            hint="Time between polls. Lower = fresher data, higher = lighter on the device."
          >
            <input
              type="number"
              className={inputCls}
              value={pollInterval}
              min={30}
              max={86400}
              onChange={(e) => setPollInterval(e.target.value)}
            />
          </Field>
          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pollInterfaces}
                onChange={(e) => setPollInterfaces(e.target.checked)}
              />
              Poll interfaces
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pollArp}
                onChange={(e) => setPollArp(e.target.checked)}
              />
              Poll ARP
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pollFdb}
                onChange={(e) => setPollFdb(e.target.checked)}
              />
              Poll FDB
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pollLldp}
                onChange={(e) => setPollLldp(e.target.checked)}
              />
              Poll LLDP
            </label>
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={autoCreate}
              onChange={(e) => setAutoCreate(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              Auto-create discovered IPs
              <span className="ml-1 text-[11px] text-muted-foreground">
                (Off by default. When on, IPs that ARP-respond and fall in a
                known subnet auto-create as &quot;discovered&quot; rows.)
              </span>
            </span>
          </label>
        </div>

        {/* Activity */}
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={isActive}
            onChange={(e) => setIsActive(e.target.checked)}
          />
          <span>Active — include in scheduled polling</span>
        </label>

        {/* Test result */}
        {testResult && <TestResultBanner result={testResult} />}

        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Footer buttons */}
        <div className="flex items-center justify-between gap-2 pt-2">
          <button
            type="button"
            onClick={() => {
              const v = validate();
              if (v) {
                setError(v);
                return;
              }
              setError(null);
              if (device?.id) {
                testMut.mutate();
              } else {
                setShowTestConfirm(true);
              }
            }}
            disabled={testMut.isPending}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
          >
            {testMut.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <TestTube2 className="h-3.5 w-3.5" />
            )}
            Test Connection
          </button>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saveMut.isPending}
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {saveMut.isPending ? "Saving…" : editing ? "Save" : "Add Device"}
            </button>
          </div>
        </div>
      </form>
      <ConfirmModal
        open={showTestConfirm}
        title="Save and test"
        message="Test Connection requires saving the device first. Save and run the test?"
        confirmLabel="Save and test"
        onConfirm={() => {
          setShowTestConfirm(false);
          testMut.mutate();
        }}
        onClose={() => setShowTestConfirm(false)}
      />
    </Modal>
  );
}

function TestResultBanner({ result }: { result: NetworkTestConnectionResult }) {
  if (result.success) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
        <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0" />
        <div className="space-y-0.5">
          <div className="font-medium">Reachable in {result.elapsed_ms} ms</div>
          {result.sys_name && (
            <div>
              <span className="text-muted-foreground">sysName:</span>{" "}
              <span className="font-mono">{result.sys_name}</span>
            </div>
          )}
          {result.sys_descr && (
            <div className="break-all">
              <span className="text-muted-foreground">sysDescr:</span>{" "}
              {result.sys_descr}
            </div>
          )}
          {result.vendor && (
            <div>
              <span className="text-muted-foreground">vendor:</span>{" "}
              {result.vendor}
            </div>
          )}
        </div>
      </div>
    );
  }
  return (
    <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
      <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
      <div className="space-y-0.5">
        <div className="font-medium">
          Test failed{result.error_kind ? ` (${result.error_kind})` : ""} after{" "}
          {result.elapsed_ms} ms
        </div>
        {result.error_message && <div>{result.error_message}</div>}
      </div>
    </div>
  );
}

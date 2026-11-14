import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, CheckCircle2, Download, Upload } from "lucide-react";

import {
  ipamApi,
  networkApi,
  type NetworkDeviceCreate,
  type NetworkDeviceRead,
  type NetworkDeviceType,
  type NetworkSnmpVersion,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { errMsg, inputCls } from "./_shared";

const EXPORT_COLUMNS = [
  "name",
  "hostname",
  "ip_address",
  "device_type",
  "description",
  "vendor",
  "snmp_version",
  "snmp_port",
  "ip_space_name",
  "is_active",
  "last_poll_status",
] as const;

const VALID_DEVICE_TYPES: NetworkDeviceType[] = [
  "router",
  "switch",
  "ap",
  "firewall",
  "l3_switch",
  "other",
];
const VALID_SNMP_VERSIONS: NetworkSnmpVersion[] = ["v1", "v2c", "v3"];

function utcSuffix(): string {
  return new Date()
    .toISOString()
    .slice(0, 19)
    .replace(/[-:]/g, "")
    .replace("T", "-");
}

// Same rule as the backend exports (sanitize_cell): a cell starting with a
// spreadsheet formula character gets a leading apostrophe so it opens as text.
const FORMULA_TRIGGERS = ["=", "+", "-", "@", "\t", "\r"];

// eslint-disable-next-line react-refresh/only-export-components
export function csvEscape(v: unknown): string {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (FORMULA_TRIGGERS.some((t) => s.startsWith(t))) s = `'${s}`;
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

// eslint-disable-next-line react-refresh/only-export-components
export function exportDevicesCsv(devices: NetworkDeviceRead[]) {
  const lines = [EXPORT_COLUMNS.join(",")];
  for (const d of devices) {
    lines.push(
      [
        d.name,
        d.hostname,
        d.ip_address,
        d.device_type,
        d.description ?? "",
        d.vendor ?? "",
        d.snmp_version,
        d.snmp_port,
        d.ip_space_name,
        d.is_active,
        d.last_poll_status,
      ]
        .map(csvEscape)
        .join(","),
    );
  }
  const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `network-devices-${utcSuffix()}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ── CSV parsing ────────────────────────────────────────────────────

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
    } else {
      if (c === '"') inQuotes = true;
      else if (c === ",") {
        row.push(cur);
        cur = "";
      } else if (c === "\n") {
        row.push(cur);
        cur = "";
        rows.push(row);
        row = [];
      } else if (c === "\r") {
        // skip
      } else {
        cur += c;
      }
    }
  }
  if (cur.length > 0 || row.length > 0) {
    row.push(cur);
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c.trim().length > 0));
}

interface ParsedRow {
  rowIndex: number;
  payload?: NetworkDeviceCreate;
  error?: string;
}

function buildRow(
  headers: string[],
  values: string[],
  spaceByName: Map<string, string>,
  spaceIds: Set<string>,
  rowIndex: number,
  defaultCommunity: string,
): ParsedRow {
  const r: Record<string, string> = {};
  for (let i = 0; i < headers.length; i++) {
    // Undo the export's formula escape (an apostrophe before a trigger).
    const cell = (values[i] ?? "").trim();
    r[headers[i]] =
      cell.length > 1 &&
      cell[0] === "'" &&
      FORMULA_TRIGGERS.some((t) => cell.slice(1).startsWith(t))
        ? cell.slice(1)
        : cell;
  }
  const name = r.name;
  const ip = r.ip_address || r.ip;
  if (!name) return { rowIndex, error: "missing name" };
  if (!ip) return { rowIndex, error: "missing ip_address" };

  let ipSpaceId = r.ip_space_id;
  if (!ipSpaceId && r.ip_space_name) {
    const match = spaceByName.get(r.ip_space_name.toLowerCase());
    if (!match)
      return { rowIndex, error: `unknown ip_space_name "${r.ip_space_name}"` };
    ipSpaceId = match;
  }
  if (!ipSpaceId)
    return { rowIndex, error: "missing ip_space_id / ip_space_name" };
  if (!spaceIds.has(ipSpaceId))
    return { rowIndex, error: `unknown ip_space_id "${ipSpaceId}"` };

  const deviceType = (r.device_type || "switch") as NetworkDeviceType;
  if (!VALID_DEVICE_TYPES.includes(deviceType))
    return { rowIndex, error: `invalid device_type "${r.device_type}"` };

  const snmpVersion = (r.snmp_version || "v2c") as NetworkSnmpVersion;
  if (!VALID_SNMP_VERSIONS.includes(snmpVersion))
    return { rowIndex, error: `invalid snmp_version "${r.snmp_version}"` };

  const port = r.snmp_port ? Number(r.snmp_port) : 161;
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    return { rowIndex, error: `invalid snmp_port "${r.snmp_port}"` };

  const isActiveRaw = (r.is_active || "true").toLowerCase();
  const isActive = !["false", "0", "no", "off"].includes(isActiveRaw);

  const payload: NetworkDeviceCreate = {
    name,
    hostname: r.hostname ?? "",
    ip_address: ip,
    device_type: deviceType,
    description: r.description || null,
    snmp_version: snmpVersion,
    snmp_port: port,
    ip_space_id: ipSpaceId,
    is_active: isActive,
  };
  if (snmpVersion !== "v3") {
    const community = r.community || defaultCommunity;
    if (community) payload.community = community;
    else
      return {
        rowIndex,
        error: "missing community (add column or set default below)",
      };
  }
  if (snmpVersion === "v3") {
    if (r.v3_security_name) payload.v3_security_name = r.v3_security_name;
    if (r.v3_security_level)
      payload.v3_security_level =
        r.v3_security_level as NetworkDeviceCreate["v3_security_level"];
    if (r.v3_auth_key) payload.v3_auth_key = r.v3_auth_key;
    if (r.v3_priv_key) payload.v3_priv_key = r.v3_priv_key;
  }
  return { rowIndex, payload };
}

// ── Modal ──────────────────────────────────────────────────────────

export function NetworkImportModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const { data: spaces = [] } = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });

  const spaceByName = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of spaces) m.set(s.name.toLowerCase(), s.id);
    return m;
  }, [spaces]);
  const spaceIds = useMemo(() => new Set(spaces.map((s) => s.id)), [spaces]);

  const [csvText, setCsvText] = useState("");
  const [defaultCommunity, setDefaultCommunity] = useState("public");
  const [parsed, setParsed] = useState<ParsedRow[] | null>(null);
  const [results, setResults] = useState<
    { rowIndex: number; ok: boolean; error?: string }[] | null
  >(null);

  function handleFile(file: File) {
    file.text().then(setCsvText);
  }

  function handlePreview() {
    setResults(null);
    const rows = parseCsv(csvText);
    if (rows.length < 2) {
      setParsed([]);
      return;
    }
    const headers = rows[0].map((h) => h.trim().toLowerCase());
    const out: ParsedRow[] = [];
    for (let i = 1; i < rows.length; i++) {
      out.push(
        buildRow(
          headers,
          rows[i],
          spaceByName,
          spaceIds,
          i + 1,
          defaultCommunity.trim(),
        ),
      );
    }
    setParsed(out);
  }

  const validRows = parsed?.filter((p) => p.payload) ?? [];

  const importMut = useMutation({
    mutationFn: async () => {
      const settled = await Promise.allSettled(
        validRows.map((r) => networkApi.createDevice(r.payload!)),
      );
      return validRows.map((r, i) => {
        const s = settled[i];
        if (s.status === "fulfilled") return { rowIndex: r.rowIndex, ok: true };
        return {
          rowIndex: r.rowIndex,
          ok: false,
          error: errMsg(s.reason, "create failed"),
        };
      });
    },
    onSuccess: (out) => {
      setResults(out);
      qc.invalidateQueries({ queryKey: ["network-devices"] });
    },
  });

  return (
    <Modal title="Import Network Devices" onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">
          CSV columns: <span className="font-mono">name</span>,{" "}
          <span className="font-mono">ip_address</span>,{" "}
          <span className="font-mono">ip_space_name</span> (or{" "}
          <span className="font-mono">ip_space_id</span>) are required.
          Optional:{" "}
          <span className="font-mono">
            hostname, device_type, description, snmp_version, snmp_port,
            community, is_active
          </span>
          .
        </p>
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Note: exports never include SNMP credentials. For v1/v2c rows missing
          a <span className="font-mono">community</span> column, the default
          below is used. For v3 rows, add{" "}
          <span className="font-mono">v3_security_name</span>,{" "}
          <span className="font-mono">v3_auth_key</span>, and{" "}
          <span className="font-mono">v3_priv_key</span> columns explicitly.
        </p>

        <div className="flex items-center gap-2">
          <label className="text-xs font-medium text-muted-foreground">
            Default community (v1/v2c)
          </label>
          <input
            type="text"
            value={defaultCommunity}
            onChange={(e) => setDefaultCommunity(e.target.value)}
            placeholder="public"
            className={`${inputCls} max-w-[200px] py-1 text-xs`}
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs hover:bg-accent">
            <Upload className="h-3.5 w-3.5" /> Choose CSV file
            <input
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
            />
          </label>
          <button
            type="button"
            onClick={handlePreview}
            disabled={!csvText.trim()}
            className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            Preview
          </button>
        </div>

        <textarea
          value={csvText}
          onChange={(e) => setCsvText(e.target.value)}
          rows={6}
          placeholder="…or paste CSV here"
          className={`${inputCls} font-mono text-[11px]`}
        />

        {parsed && (
          <div className="rounded-md border">
            <div className="flex items-center justify-between border-b bg-muted/30 px-3 py-2 text-xs">
              <span>
                {validRows.length} valid · {parsed.length - validRows.length}{" "}
                error{parsed.length - validRows.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="max-h-64 overflow-auto">
              <table className="w-full text-[11px]">
                <thead>
                  <tr className="border-b bg-muted/10 text-left">
                    <th className="px-2 py-1">Row</th>
                    <th className="px-2 py-1">Name</th>
                    <th className="px-2 py-1">IP</th>
                    <th className="px-2 py-1">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {parsed.map((r) => {
                    const result = results?.find(
                      (x) => x.rowIndex === r.rowIndex,
                    );
                    return (
                      <tr key={r.rowIndex} className="border-b last:border-0">
                        <td className="px-2 py-1 tabular-nums text-muted-foreground">
                          {r.rowIndex}
                        </td>
                        <td className="px-2 py-1">{r.payload?.name ?? "—"}</td>
                        <td className="px-2 py-1 font-mono">
                          {r.payload?.ip_address ?? "—"}
                        </td>
                        <td className="px-2 py-1">
                          {result ? (
                            result.ok ? (
                              <span className="inline-flex items-center gap-1 text-emerald-600">
                                <CheckCircle2 className="h-3 w-3" /> created
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-red-600">
                                <AlertCircle className="h-3 w-3" />{" "}
                                {result.error}
                              </span>
                            )
                          ) : r.error ? (
                            <span className="text-red-600">{r.error}</span>
                          ) : (
                            <span className="text-emerald-600">ready</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
          >
            Close
          </button>
          <button
            type="button"
            onClick={() => importMut.mutate()}
            disabled={
              validRows.length === 0 || importMut.isPending || !!results
            }
            className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            <Download className="mr-1 inline h-3 w-3 rotate-180" />
            {importMut.isPending
              ? "Importing…"
              : `Import ${validRows.length} device${validRows.length === 1 ? "" : "s"}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}

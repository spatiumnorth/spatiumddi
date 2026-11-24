import { useMemo, useState } from "react";
import { Calculator } from "lucide-react";

type ParsedCidr = {
  family: 4 | 6;
  address: bigint;
  prefix: number;
  rawAddress: string;
};

type CalcResult =
  | {
      ok: true;
      family: 4 | 6;
      rows: { label: string; value: string; mono?: boolean }[];
      binary?: string[];
    }
  | { ok: false; error: string };

const V4_BITS = 32;
const V6_BITS = 128;

function parseIPv4(addr: string): bigint | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return n;
}

function formatIPv4(n: bigint): string {
  return [
    Number((n >> 24n) & 0xffn),
    Number((n >> 16n) & 0xffn),
    Number((n >> 8n) & 0xffn),
    Number(n & 0xffn),
  ].join(".");
}

function parseIPv6(addr: string): bigint | null {
  // Reject obviously malformed inputs early.
  if (!/^[0-9a-fA-F:]+$/.test(addr)) return null;
  const doubleColonCount = (addr.match(/::/g) || []).length;
  if (doubleColonCount > 1) return null;

  let head: string[];
  let tail: string[];
  if (doubleColonCount === 1) {
    const [h, t] = addr.split("::");
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
  } else {
    head = addr.split(":");
    tail = [];
  }
  const total = head.length + tail.length;
  if (doubleColonCount === 0 && total !== 8) return null;
  if (doubleColonCount === 1 && total > 7) return null;
  const fillCount = 8 - total;
  const groups = [...head, ...Array(fillCount).fill("0"), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (g.length === 0 || g.length > 4) return null;
    const v = parseInt(g, 16);
    if (Number.isNaN(v)) return null;
    n = (n << 16n) | BigInt(v);
  }
  return n;
}

function formatIPv6Full(n: bigint): string {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) {
    const g = Number((n >> BigInt(i * 16)) & 0xffffn);
    groups.push(g.toString(16).padStart(4, "0"));
  }
  return groups.join(":");
}

function compressIPv6(n: bigint): string {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) {
    const g = Number((n >> BigInt(i * 16)) & 0xffffn);
    groups.push(g.toString(16));
  }
  // Find the longest run of zeros (length >= 2).
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

function parseCidr(input: string): ParsedCidr | { error: string } {
  const trimmed = input.trim();
  if (!trimmed) return { error: "Enter a CIDR (e.g. 192.168.1.0/24)" };
  const slash = trimmed.indexOf("/");
  let addrPart: string;
  let prefixPart: string | null;
  if (slash === -1) {
    addrPart = trimmed;
    prefixPart = null;
  } else {
    addrPart = trimmed.slice(0, slash);
    prefixPart = trimmed.slice(slash + 1);
  }

  const isV6 = addrPart.includes(":");
  const family: 4 | 6 = isV6 ? 6 : 4;
  const bits = family === 4 ? V4_BITS : V6_BITS;
  let prefix: number;
  if (prefixPart === null) {
    prefix = bits;
  } else {
    if (!/^\d+$/.test(prefixPart)) return { error: "Prefix must be a number" };
    prefix = Number(prefixPart);
    if (prefix < 0 || prefix > bits)
      return { error: `Prefix must be 0–${bits} for IPv${family}` };
  }

  const address = family === 4 ? parseIPv4(addrPart) : parseIPv6(addrPart);
  if (address === null)
    return { error: `Invalid IPv${family} address: ${addrPart}` };

  return { family, address, prefix, rawAddress: addrPart };
}

function ipv4ToBinary(n: bigint): string {
  const full = n.toString(2).padStart(32, "0");
  return full.match(/.{8}/g)!.join(".");
}

function compute(input: string): CalcResult {
  const parsed = parseCidr(input);
  if ("error" in parsed) return { ok: false, error: parsed.error };

  const { family, address, prefix } = parsed;
  const bits = family === 4 ? V4_BITS : V6_BITS;
  const hostBits = bits - prefix;
  const fullMask = (1n << BigInt(bits)) - 1n;
  const networkMask =
    hostBits === bits ? 0n : (fullMask >> BigInt(hostBits)) << BigInt(hostBits);
  const wildcard = fullMask ^ networkMask;
  const network = address & networkMask;
  const broadcast = network | wildcard;
  const totalAddresses = 1n << BigInt(hostBits);

  const rows: { label: string; value: string; mono?: boolean }[] = [];
  let binary: string[] | undefined;

  if (family === 4) {
    const usable =
      hostBits >= 2 ? totalAddresses - 2n : hostBits === 1 ? 2n : 1n;
    const firstUsable = hostBits >= 2 ? network + 1n : network;
    const lastUsable = hostBits >= 2 ? broadcast - 1n : broadcast;

    rows.push(
      {
        label: "Network",
        value: `${formatIPv4(network)}/${prefix}`,
        mono: true,
      },
      { label: "Netmask", value: formatIPv4(networkMask), mono: true },
      { label: "Wildcard", value: formatIPv4(wildcard), mono: true },
      { label: "Broadcast", value: formatIPv4(broadcast), mono: true },
      { label: "First usable", value: formatIPv4(firstUsable), mono: true },
      { label: "Last usable", value: formatIPv4(lastUsable), mono: true },
      { label: "Total addresses", value: totalAddresses.toLocaleString() },
      { label: "Usable hosts", value: usable.toLocaleString() },
      { label: "Decimal", value: network.toString(), mono: true },
      {
        label: "Hex",
        value: `0x${network.toString(16).toUpperCase()}`,
        mono: true,
      },
    );
    binary = [
      `Address  : ${ipv4ToBinary(address)}`,
      `Netmask  : ${ipv4ToBinary(networkMask)}`,
      `Wildcard : ${ipv4ToBinary(wildcard)}`,
      `Network  : ${ipv4ToBinary(network)}`,
    ];
  } else {
    const firstUsable = network;
    const lastUsable = broadcast;
    rows.push(
      {
        label: "Network",
        value: `${compressIPv6(network)}/${prefix}`,
        mono: true,
      },
      {
        label: "Network (expanded)",
        value: formatIPv6Full(network),
        mono: true,
      },
      { label: "Last address", value: compressIPv6(broadcast), mono: true },
      {
        label: "Last (expanded)",
        value: formatIPv6Full(broadcast),
        mono: true,
      },
      { label: "First usable", value: compressIPv6(firstUsable), mono: true },
      { label: "Last usable", value: compressIPv6(lastUsable), mono: true },
      { label: "Total addresses", value: totalAddresses.toString() },
      {
        label: "Hex",
        value: `0x${network.toString(16).toUpperCase()}`,
        mono: true,
      },
    );
  }

  return { ok: true, family, rows, binary };
}

const PRESETS = [
  "10.0.0.0/8",
  "192.168.1.0/24",
  "172.16.0.0/12",
  "100.64.0.0/10",
  "2001:db8::/32",
  "fd00::/8",
];

export function CidrCalculatorPage() {
  const [input, setInput] = useState("192.168.1.0/24");
  const result = useMemo(() => compute(input), [input]);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center gap-2">
          <Calculator className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">CIDR calculator</h1>
        </div>
        <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
          Pure client-side calculator — paste any IPv4 or IPv6 CIDR (or a bare
          address) and see network / netmask / wildcard / range / binary
          breakdowns. Nothing leaves the browser.
        </p>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg border bg-card p-4">
            <label
              htmlFor="cidr-calculator-cidr-or-address"
              className="mb-2 block text-xs font-medium text-muted-foreground"
            >
              CIDR or address
            </label>
            <input
              id="cidr-calculator-cidr-or-address"
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="192.168.1.0/24 or 2001:db8::/48"
              className="w-full rounded-md border bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-ring"
              autoFocus
              spellCheck={false}
            />
            <div className="mt-3 flex flex-wrap gap-1.5">
              {PRESETS.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setInput(p)}
                  className="rounded border bg-muted/30 px-2 py-0.5 font-mono text-[11px] text-muted-foreground hover:bg-muted/60"
                >
                  {p}
                </button>
              ))}
            </div>
            {!result.ok && (
              <p className="mt-3 text-xs text-destructive">{result.error}</p>
            )}
          </div>

          <div className="rounded-lg border bg-card p-4">
            <h2 className="mb-3 text-sm font-medium">
              {result.ok ? `IPv${result.family} breakdown` : "Breakdown"}
            </h2>
            {result.ok ? (
              <table className="w-full text-xs">
                <tbody>
                  {result.rows.map((r) => (
                    <tr key={r.label} className="border-b last:border-0">
                      <td className="py-1.5 pr-3 text-muted-foreground">
                        {r.label}
                      </td>
                      <td
                        className={`py-1.5 ${r.mono ? "font-mono" : ""} break-all`}
                      >
                        {r.value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-xs text-muted-foreground">
                Enter a valid CIDR to see the breakdown.
              </p>
            )}
          </div>
        </div>

        {result.ok && result.binary && (
          <div className="mt-4 rounded-lg border bg-card p-4">
            <h2 className="mb-2 text-sm font-medium">Binary</h2>
            <pre className="overflow-x-auto rounded bg-muted/30 p-3 font-mono text-[11px] leading-relaxed">
              {result.binary.join("\n")}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

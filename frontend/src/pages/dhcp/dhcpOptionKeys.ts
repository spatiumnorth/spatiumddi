import type { DHCPOption } from "@/lib/api";

/**
 * Map-shaped option stores (option templates, client classes) keyed the way
 * the backend's option check (#1228) accepts them. Mirrors
 * `normalize_options` in `backend/app/services/dhcp/option_validation.py`:
 * a canonical SpatiumDDI name is kept, and anything else picked from the
 * option-code catalogue is keyed by the raw code it can be delivered as.
 * Keying a catalogue pick by its IANA name (`vendor-encapsulated-options`)
 * or by `option-NN` is refused with a 422, because the renderer drops both.
 */
const CANONICAL_CODES: Record<string, number> = {
  "time-offset": 2,
  routers: 3,
  "dns-servers": 6,
  "domain-name": 15,
  mtu: 26,
  "broadcast-address": 28,
  "ntp-servers": 42,
  "tftp-server-name": 66,
  "bootfile-name": 67,
  "domain-search": 119,
  "tftp-server-address": 150,
};

const RAW_KEY = /^(?:code:|opt-)(\d+)$/;

/** How a group's servers spell a raw option code (#1347): Windows reads
 *  `opt-NN` and drops `code:NN`; Kea and FortiGate the reverse. Mirrors
 *  `spelling_for_drivers` in `backend/app/services/dhcp/option_spelling.py`
 *  for the one case the editor can act on: an all-Windows group. */
export type RawPrefix = "code:" | "opt-";

export function rawPrefixFor(drivers: string[]): RawPrefix {
  return drivers.length > 0 && drivers.every((d) => d === "windows_dhcp")
    ? "opt-"
    : "code:";
}

/** The option code a stored key stands for, or 0 when it names none. */
export function optionKeyCode(key: string): number {
  if (key in CANONICAL_CODES) return CANONICAL_CODES[key];
  const m = RAW_KEY.exec(key);
  return m ? parseInt(m[1], 10) : 0;
}

/** The key one editor row is stored under. */
export function optionKey(
  opt: DHCPOption,
  rawPrefix: RawPrefix = "code:",
): string {
  const name = opt.name ?? "";
  if (name in CANONICAL_CODES) return name;
  // A raw-code row keeps its own spelling (an imported `opt-NN` re-keyed
  // as `code:NN` would be a new option to the backend, and re-checked);
  // only a retyped code box changes the number.
  const raw = RAW_KEY.exec(name);
  if (raw) {
    const prefix = name.startsWith("opt-") ? "opt-" : "code:";
    return opt.code > 0 ? `${prefix}${opt.code}` : name;
  }
  if (opt.code > 0) {
    const canonical = Object.entries(CANONICAL_CODES).find(
      ([, c]) => c === opt.code,
    );
    return canonical ? canonical[0] : `${rawPrefix}${opt.code}`;
  }
  return name;
}

export function optionsToMap(
  options: DHCPOption[],
  rawPrefix: RawPrefix = "code:",
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const opt of options) {
    const key = optionKey(opt, rawPrefix);
    if (key) out[key] = opt.value;
  }
  return out;
}

export function optionsFromMap(
  map: Record<string, unknown> | null | undefined,
): DHCPOption[] {
  return Object.entries(map ?? {}).map(([name, value]) => ({
    code: optionKeyCode(name),
    name,
    value: value as string | string[],
  }));
}

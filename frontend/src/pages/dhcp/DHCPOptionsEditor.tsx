import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Plus, X } from "lucide-react";
import { dhcpApi, type DHCPOption, type DHCPOptionCodeDef } from "@/lib/api";
import { closePopupOnEscape } from "@/components/ui/use-draggable-modal";
import { Field, inputCls } from "./_shared";

/**
 * Editor for a set of DHCP options (standard + custom). Used in scope, pool,
 * and static-assignment modals.
 *
 * The value format `DHCPOption[]` uses either `value: string` (single-value
 * options like Domain Name or Bootfile Name) or `value: string[]` (list
 * options like Routers, DNS Servers, NTP Servers).
 *
 * NTP (option 42) is a first-class labeled input — SpatiumDDI treats NTP
 * as a peer of DNS/DHCP, so it must be visible without diving into a
 * custom-options accordion.
 */
interface StandardDef {
  code: number;
  name: string;
  label: string;
  hint?: string;
  kind: "ip-list" | "string" | "ip";
}

const STANDARD_OPTIONS: StandardDef[] = [
  {
    code: 3,
    name: "routers",
    label: "Routers (option 3)",
    kind: "ip-list",
    hint: "Default gateway(s) for clients on this scope.",
  },
  {
    // Canonical SpatiumDDI option name is ``dns-servers`` — this is what
    // the backend stores + what the Kea driver's option-name map keys on
    // (both v4 → ``domain-name-servers`` and v6 → option 23). Sending the
    // IANA name ``domain-name-servers`` here bypassed that map and, worse,
    // read back as code 0 so the field rendered empty on edit (#583).
    code: 6,
    name: "dns-servers",
    label: "DNS Servers (option 6)",
    kind: "ip-list",
    // #2482 — no cap: the cut on blur dropped a stored 4th server while the
    // input still showed it. The API stores the whole list, and so do we.
    hint: "DNS resolver IPs; clients commonly use the first 3.",
  },
  {
    code: 15,
    name: "domain-name",
    label: "Domain Name (option 15)",
    kind: "string",
  },
  {
    code: 42,
    name: "ntp-servers",
    label: "NTP Servers (option 42)",
    kind: "ip-list",
    hint: "Time-sync servers pushed to clients. Required for Kerberos, TLS certs, and audit accuracy.",
  },
  {
    code: 66,
    name: "tftp-server-name",
    label: "TFTP Server Name (option 66)",
    kind: "string",
    hint: "Hostname or IP string for PXE/firmware download.",
  },
  {
    code: 67,
    name: "bootfile-name",
    label: "Bootfile Name (option 67)",
    kind: "string",
  },
  {
    code: 119,
    name: "domain-search",
    label: "Domain Search (option 119)",
    kind: "ip-list",
    hint: "Search-domain suffixes (comma-separated).",
  },
  {
    code: 150,
    name: "tftp-server-address",
    label: "TFTP Server Address (option 150)",
    kind: "ip-list",
    hint: "List of TFTP server IPs (Cisco phones, etc).",
  },
];

function splitList(s: string): string[] {
  return s
    .split(/[,\s]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function joinList(xs: string[] | string | undefined): string {
  if (!xs) return "";
  if (Array.isArray(xs)) return xs.join(", ");
  return xs;
}

function CustomOptionRow({
  opt,
  catalog,
  onChange,
  onRemove,
}: {
  opt: DHCPOption;
  catalog: DHCPOptionCodeDef[];
  onChange: (next: DHCPOption) => void;
  onRemove: () => void;
}) {
  const [query, setQuery] = useState<string>(
    opt.code ? `${opt.code} — ${opt.name ?? ""}`.trim() : "",
  );
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);
  // Reflect changes to the row's code into the box (a catalogue pick, a
  // typed code committed on blur / Enter, a template apply). The box never
  // writes the code per keystroke (#1685): doing so let this effect rewrite
  // "4" to "4 —" before the "3" of "43" landed, and turned the row into a
  // standard option (3, 6, 15, 42…) mid-way through typing a longer code,
  // dropping it out of the custom list.
  //
  // Keyed on the row object, not just its code: rows are keyed by index, so
  // deleting one hands this instance the next row, which may carry the same
  // code — and the box must not keep the deleted row's half-typed text.
  // Nothing replaces the object while the operator types in the box.
  useEffect(() => {
    setQuery(opt.code ? `${opt.code} — ${opt.name ?? ""}`.trim() : "");
  }, [opt]);

  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (
        wrapperRef.current &&
        !wrapperRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return catalog.slice(0, 25);
    const isNum = /^\d+$/.test(needle);
    return catalog
      .filter((d) => {
        if (isNum) return String(d.code).startsWith(needle);
        return (
          d.name.toLowerCase().includes(needle) ||
          d.description.toLowerCase().includes(needle)
        );
      })
      .slice(0, 25);
  }, [catalog, query]);

  const knownDef = useMemo(
    () => catalog.find((d) => d.code === opt.code),
    [catalog, opt.code],
  );

  function pick(def: DHCPOptionCodeDef) {
    onChange({ ...opt, code: def.code, name: def.name });
    setQuery(`${def.code} — ${def.name}`);
    setOpen(false);
  }

  // Commit a typed code to the row, so an operator can type "42" + Tab and
  // have a custom code (known to the catalogue or not) stick. Text that
  // doesn't start with a number leaves the code alone and the box settles
  // back to "<code> — <name>".
  function commitTyped() {
    const numMatch = /^(\d+)/.exec(query.trim());
    if (numMatch) {
      const n = parseInt(numMatch[1], 10);
      if (!Number.isNaN(n) && n !== opt.code) {
        // The name follows the code: a stale name from the previous code
        // would otherwise travel with the new one.
        const def = catalog.find((d) => d.code === n);
        onChange({ ...opt, code: n, name: def?.name });
        return;
      }
    }
    setQuery(opt.code ? `${opt.code} — ${opt.name ?? ""}`.trim() : "");
  }

  return (
    <div className="space-y-1">
      <div className="flex items-start gap-2">
        <div ref={wrapperRef} className="relative w-72 shrink-0">
          <input
            className={inputCls}
            placeholder="Search code or name…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            onBlur={commitTyped}
            onKeyDown={(e) => {
              if (
                closePopupOnEscape(e, open && matches.length > 0, () =>
                  setOpen(false),
                )
              )
                return;
              // Enter commits the typed code instead of submitting the
              // surrounding form with the row still on its old code.
              if (e.key === "Enter") {
                e.preventDefault();
                commitTyped();
                setOpen(false);
              }
            }}
          />
          {open && matches.length > 0 && (
            <div className="absolute left-0 right-0 top-full z-20 mt-1 max-h-72 overflow-y-auto rounded-md border bg-popover shadow-md">
              {matches.map((def) => (
                <button
                  key={def.code}
                  type="button"
                  // Keep focus in the box: a blur here would commit the
                  // partly-typed code first, and a standard code ("6" on
                  // the way to 60) moves the row out of this list before
                  // the click lands.
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => pick(def)}
                  className="block w-full px-3 py-1.5 text-left text-xs hover:bg-accent"
                >
                  <div className="font-mono">
                    {def.code} — <span className="font-sans">{def.name}</span>
                  </div>
                  {def.description && (
                    <div className="truncate text-[11px] text-muted-foreground">
                      {def.description}
                    </div>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
        <input
          className="min-w-0 flex-1 rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="value"
          value={
            typeof opt.value === "string" ? opt.value : opt.value.join(", ")
          }
          onChange={(e) => onChange({ ...opt, value: e.target.value })}
        />
        <button
          type="button"
          // No blur-commit on the way to a delete: committing a half-typed
          // standard code ("6") would move this row out of the list, and the
          // click would then land on the next row's button.
          onMouseDown={(e) => e.preventDefault()}
          onClick={onRemove}
          aria-label="Remove option"
          title="Remove option"
          className="rounded p-1 text-muted-foreground hover:text-destructive"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
      {knownDef?.description && (
        <div className="ml-1 text-[11px] text-muted-foreground">
          {knownDef.description}
        </div>
      )}
    </div>
  );
}

export function DHCPOptionsEditor({
  value,
  onChange,
}: {
  value: DHCPOption[];
  onChange: (next: DHCPOption[]) => void;
}) {
  const byCode = useMemo(() => {
    const m = new Map<number, DHCPOption>();
    for (const o of value) m.set(o.code, o);
    return m;
  }, [value]);

  const [showCustom, setShowCustom] = useState(false);

  const { data: catalog = [] } = useQuery({
    queryKey: ["dhcp-option-codes"],
    queryFn: () => dhcpApi.listOptionCodes(),
    staleTime: Infinity,
    gcTime: Infinity,
  });

  function setStandard(def: StandardDef, rawInput: string) {
    const clean = rawInput.trim();
    const next = value.filter((o) => o.code !== def.code);
    if (!clean) {
      onChange(next);
      return;
    }
    if (def.kind === "string") {
      next.push({ code: def.code, name: def.name, value: clean });
    } else if (def.kind === "ip" || def.kind === "ip-list") {
      const list = splitList(clean);
      next.push({ code: def.code, name: def.name, value: list });
    }
    onChange(next);
  }

  const customOptions = value.filter(
    (o) => !STANDARD_OPTIONS.some((s) => s.code === o.code),
  );

  function updateCustomAt(idx: number, next: DHCPOption) {
    const fullIdx = value.findIndex(
      (o) =>
        o === customOptions[idx] ||
        (o.code === customOptions[idx].code &&
          o.value === customOptions[idx].value),
    );
    if (fullIdx < 0) return;
    const out = [...value];
    out[fullIdx] = next;
    onChange(out);
  }

  function removeCustomAt(idx: number) {
    onChange(value.filter((o) => o !== customOptions[idx]));
  }

  return (
    <div className="space-y-3">
      {STANDARD_OPTIONS.map((def) => {
        const current = byCode.get(def.code);
        const rendered = joinList(current?.value);
        return (
          <div key={def.code}>
            <Field label={def.label} hint={def.hint}>
              <input
                className={inputCls}
                placeholder={
                  def.kind === "ip-list"
                    ? "e.g. 10.0.0.1, 10.0.0.2"
                    : def.kind === "string"
                      ? ""
                      : "e.g. 10.0.0.1"
                }
                defaultValue={rendered}
                onBlur={(e) => setStandard(def, e.target.value)}
                // #3085 — the field hands its text over on blur, and Enter
                // submits the surrounding form with no blur: the dialog
                // would save the options as they were before the typing.
                // Commit the field and keep the dialog open, as the code
                // picker above does. An Enter that confirms an IME
                // composition is left to the IME.
                onKeyDown={(e) => {
                  if (
                    e.key === "Enter" &&
                    !e.nativeEvent.isComposing &&
                    e.keyCode !== 229
                  ) {
                    e.preventDefault();
                    setStandard(def, e.currentTarget.value);
                  }
                }}
              />
            </Field>
          </div>
        );
      })}

      <div className="border-t pt-3">
        <button
          type="button"
          onClick={() => setShowCustom((v) => !v)}
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          {showCustom ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
          Custom options{" "}
          {customOptions.length > 0 && `(${customOptions.length})`}
        </button>

        {showCustom && (
          <div className="mt-2 space-y-3">
            {customOptions.map((opt, idx) => (
              <CustomOptionRow
                key={idx}
                opt={opt}
                catalog={catalog}
                onChange={(next) => updateCustomAt(idx, next)}
                onRemove={() => removeCustomAt(idx)}
              />
            ))}
            <button
              type="button"
              onClick={() => onChange([...value, { code: 0, value: "" }])}
              className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
            >
              <Plus className="h-3 w-3" /> Add custom option
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

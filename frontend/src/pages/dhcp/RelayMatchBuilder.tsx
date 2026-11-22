import { useEffect, useRef, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  dhcpApi,
  type CompileMatchResult,
  type RelayMatchCondition,
  type RelayMatchOp,
  type RelayMatchSpec,
} from "@/lib/api";
import { errMsg, inputCls } from "./_shared";

// #54 — structured option 82 match. Controlled: the parent holds the spec and
// the server (compile-match) stays authoritative for validation and for the
// Kea test the spec compiles to.

const MAX_CONDITIONS = 16;

const NAMED_SUB_OPTIONS: Array<[number, string]> = [
  [1, "Circuit ID (1)"],
  [2, "Remote ID (2)"],
  [6, "Subscriber ID (6)"],
  [12, "Relay ID (12)"],
];
const NAMED_CODES = NAMED_SUB_OPTIONS.map(([c]) => c);

const OPS: Array<[RelayMatchOp, string]> = [
  ["exists", "exists"],
  ["not_exists", "does not exist"],
  ["equals", "equals"],
  ["not_equals", "does not equal"],
  ["starts_with", "starts with"],
  ["ends_with", "ends with"],
  ["slice", "bytes at offset"],
];

// eslint-disable-next-line react-refresh/only-export-components
export const EMPTY_RELAY_SPEC: RelayMatchSpec = {
  kind: "relay_agent",
  combine: "all",
  conditions: [{ sub_option: 1, op: "equals", encoding: "text", value: "" }],
};

const isExistence = (op: RelayMatchOp) =>
  op === "exists" || op === "not_exists";

export function RelayMatchBuilder({
  value,
  onChange,
  onCompiled,
}: {
  value: RelayMatchSpec;
  onChange: (spec: RelayMatchSpec) => void;
  // Latest compile outcome for a spec (its JSON key); expression is null when
  // the server refused it. Lets the parent seed a hand-written test from what
  // the current, possibly unsaved, spec compiles to.
  onCompiled?: (specKey: string, expression: string | null) => void;
}) {
  // Rows showing the free sub-option number input, parallel to conditions. A
  // typed 6 must not flip the row back to the named select mid-edit.
  const [custom, setCustom] = useState<boolean[]>(() =>
    value.conditions.map((c) => !NAMED_CODES.includes(c.sub_option)),
  );
  const [preview, setPreview] = useState<CompileMatchResult | null>(null);
  const [previewError, setPreviewError] = useState("");

  const setCondition = (i: number, patch: Partial<RelayMatchCondition>) => {
    const next = value.conditions.map((c, j) => {
      if (j !== i) return c;
      const merged: RelayMatchCondition = { ...c, ...patch };
      // Keep the wire shape clean: no value on exists ops, no offset off slice.
      if (isExistence(merged.op)) {
        delete merged.value;
        delete merged.offset;
      } else {
        merged.value ??= "";
        if (merged.op === "slice") merged.offset ??= 0;
        else delete merged.offset;
      }
      return merged;
    });
    onChange({ ...value, conditions: next });
  };

  const add = () => {
    setCustom([...custom, false]);
    onChange({
      ...value,
      conditions: [
        ...value.conditions,
        { sub_option: 1, op: "equals", encoding: "text", value: "" },
      ],
    });
  };
  const remove = (i: number) => {
    setCustom(custom.filter((_, j) => j !== i));
    onChange({
      ...value,
      conditions: value.conditions.filter((_, j) => j !== i),
    });
  };

  // Debounced live preview from the server compiler.
  const specKey = JSON.stringify(value);
  const onCompiledRef = useRef(onCompiled);
  onCompiledRef.current = onCompiled;
  useEffect(() => {
    let live = true;
    const t = setTimeout(() => {
      dhcpApi
        .compileClientClassMatch(JSON.parse(specKey) as RelayMatchSpec)
        .then((r) => {
          if (!live) return;
          setPreview(r);
          setPreviewError("");
          onCompiledRef.current?.(specKey, r.expression);
        })
        .catch((e) => {
          if (!live) return;
          setPreview(null);
          setPreviewError(errMsg(e, "Could not compile this match"));
          onCompiledRef.current?.(specKey, null);
        });
    }, 400);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [specKey]);

  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex items-center gap-2 text-sm">
        <span>Match</span>
        <select
          aria-label="Combine conditions"
          className={`${inputCls} !w-auto`}
          value={value.combine}
          onChange={(e) =>
            onChange({ ...value, combine: e.target.value as "all" | "any" })
          }
        >
          <option value="all">all</option>
          <option value="any">any</option>
        </select>
        <span>of these conditions:</span>
      </div>

      {value.conditions.map((c, i) => {
        const n = i + 1;
        const isCustom = custom[i] ?? !NAMED_CODES.includes(c.sub_option);
        return (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <select
              aria-label={`Condition ${n} sub-option`}
              className={`${inputCls} !w-auto`}
              value={isCustom ? "other" : String(c.sub_option)}
              onChange={(e) => {
                const other = e.target.value === "other";
                setCustom(custom.map((x, j) => (j === i ? other : x)));
                setCondition(i, {
                  sub_option: other ? 3 : Number(e.target.value),
                });
              }}
            >
              {NAMED_SUB_OPTIONS.map(([code, label]) => (
                <option key={code} value={code}>
                  {label}
                </option>
              ))}
              <option value="other">Other…</option>
            </select>
            {isCustom && (
              <input
                type="number"
                min={1}
                max={255}
                aria-label={`Condition ${n} sub-option code`}
                className={`${inputCls} !w-20`}
                value={Number.isNaN(c.sub_option) ? "" : c.sub_option}
                onChange={(e) =>
                  setCondition(i, {
                    sub_option:
                      e.target.value === "" ? NaN : Number(e.target.value),
                  })
                }
              />
            )}
            <select
              aria-label={`Condition ${n} operator`}
              className={`${inputCls} !w-auto`}
              value={c.op}
              onChange={(e) =>
                setCondition(i, { op: e.target.value as RelayMatchOp })
              }
            >
              {OPS.map(([op, label]) => (
                <option key={op} value={op}>
                  {label}
                </option>
              ))}
            </select>
            {c.op === "slice" && (
              <input
                type="number"
                min={0}
                max={254}
                aria-label={`Condition ${n} offset`}
                placeholder="offset"
                className={`${inputCls} !w-20`}
                value={c.offset ?? ""}
                onChange={(e) =>
                  setCondition(i, {
                    offset:
                      e.target.value === ""
                        ? undefined
                        : Number(e.target.value),
                  })
                }
              />
            )}
            {!isExistence(c.op) && (
              <>
                <input
                  aria-label={`Condition ${n} value`}
                  className={`${inputCls} !w-56 font-mono text-xs`}
                  value={c.value ?? ""}
                  onChange={(e) => setCondition(i, { value: e.target.value })}
                />
                <div
                  role="group"
                  aria-label={`Condition ${n} encoding`}
                  className="inline-flex overflow-hidden rounded-md border text-xs"
                >
                  {(["text", "hex"] as const).map((enc) => (
                    <button
                      key={enc}
                      type="button"
                      aria-pressed={c.encoding === enc}
                      onClick={() => setCondition(i, { encoding: enc })}
                      className={`px-2 py-1 ${
                        c.encoding === enc
                          ? "bg-primary text-primary-foreground"
                          : "hover:bg-accent"
                      }`}
                    >
                      {enc === "text" ? "Text" : "Hex"}
                    </button>
                  ))}
                </div>
              </>
            )}
            <button
              type="button"
              aria-label={`Remove condition ${n}`}
              disabled={value.conditions.length <= 1}
              onClick={() => remove(i)}
              className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-destructive disabled:opacity-40"
            >
              <Trash2 className="h-4 w-4" />
            </button>
          </div>
        );
      })}

      <button
        type="button"
        onClick={add}
        disabled={value.conditions.length >= MAX_CONDITIONS}
        className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
      >
        <Plus className="h-3 w-3" /> Add condition
      </button>

      <div>
        <div className="mb-1 text-xs font-medium">Kea test (preview)</div>
        <div aria-live="polite">
          {previewError ? (
            <div role="alert" className="text-xs text-destructive">
              {previewError}
            </div>
          ) : (
            <pre
              data-testid="relay-preview"
              className="overflow-x-auto rounded-md bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-all"
            >
              {preview?.expression ?? "…"}
            </pre>
          )}
          {preview?.warnings.map((w, i) => (
            <p key={i} className="mt-1 text-xs text-amber-600">
              {w}
            </p>
          ))}
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Renewals arrive without a relay in the path, so Kea has to keep each
        client&apos;s relay information to keep matching. SpatiumDDI turns on
        Kea&apos;s relay-info retention automatically for server groups that
        have an option 82 class.
      </p>
    </div>
  );
}

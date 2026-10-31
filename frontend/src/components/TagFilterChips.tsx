import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Tag, X } from "lucide-react";
import { tagsApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { closePopupOnEscape } from "@/components/ui/use-draggable-modal";

/**
 * Free-form tag filter chips with key/value autocomplete (issue #104
 * phase 3). Mirrors the AI copilot's ``find_by_tag`` argument shape
 * so the conversion model is operator-obvious — the wire form is
 * literally what the operator types.
 *
 * # Wire shape
 *
 * Each chip is one of:
 *
 * * ``key`` — match rows where the key is present, any value
 * * ``key:value`` — exact match on ``tags[key] == value``
 *
 * Multiple chips AND together. The component emits the array of
 * chip strings via ``onChange``; the parent threads them straight
 * into the ``?tag=`` query param of whichever list endpoint it's
 * filtering. No serialisation translation needed in the parent —
 * the chip *is* the query value.
 *
 * # UX flow
 *
 * 1. Operator clicks the empty input — autocomplete opens with the
 *    first page of distinct keys across every tagged resource type
 *    (``GET /tags/keys``).
 * 2. Typing narrows the dropdown via the endpoint's ``prefix=``
 *    arg — keeps the wire matching whatever the database has.
 * 3. The first ``:`` flips the dropdown source to
 *    ``GET /tags/values?key=<typed-key>`` so the operator picks
 *    from the values that actually exist for that key.
 * 4. Pressing Enter (or clicking a dropdown row) commits a chip.
 *    Empty / duplicate inputs are silently no-ops.
 * 5. Backspace on the empty textbox pops the last chip — matches
 *    the affordance gmail / Slack tag pickers train operators on.
 *
 * # Keyboard
 *
 * Enter commits, Escape cancels editing (drops the in-flight
 * input). Up/Down on the dropdown is intentionally not wired for
 * v1 — operators almost always have a hand on the mouse for chip
 * picking and the click affordance is enough.
 */
export function TagFilterChips({
  value,
  onChange,
  placeholder = "Filter by tag (key or key:value)…",
  className,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  className?: string;
}) {
  const [input, setInput] = useState("");
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Split the typed text on the first colon — same partition rule
  // the backend's ``parse_tag_param`` uses, so what the operator sees
  // in the dropdown matches what the filter will actually do.
  const colonIdx = input.indexOf(":");
  const typingValue = colonIdx >= 0;
  const typedKey = typingValue ? input.slice(0, colonIdx).trim() : null;
  const valuePrefix = typingValue ? input.slice(colonIdx + 1) : "";
  const keyPrefix = typingValue ? "" : input;

  const keysQ = useQuery({
    queryKey: ["tag-keys", keyPrefix],
    queryFn: () => tagsApi.listKeys(keyPrefix || undefined, 50),
    enabled: focused && !typingValue,
    // Operators rarely invent new keys mid-session — generous cache
    // so each keystroke doesn't burn a request.
    staleTime: 30_000,
  });

  const valuesQ = useQuery({
    queryKey: ["tag-values", typedKey, valuePrefix],
    queryFn: () => tagsApi.listValues(typedKey!, valuePrefix || undefined, 50),
    enabled: focused && typingValue && !!typedKey,
    staleTime: 30_000,
  });

  const dropdownItems = useMemo<string[]>(() => {
    if (!focused) return [];
    if (typingValue && typedKey) {
      return (valuesQ.data?.values ?? []).map((v) => `${typedKey}:${v}`);
    }
    return keysQ.data?.keys ?? [];
  }, [focused, typingValue, typedKey, keysQ.data, valuesQ.data]);

  function commit(raw: string) {
    const trimmed = raw.trim();
    if (!trimmed) return;
    if (value.includes(trimmed)) return; // dedupe — same chip twice would AND with itself, no-op
    onChange([...value, trimmed]);
    setInput("");
  }

  function removeAt(idx: number) {
    onChange(value.filter((_, i) => i !== idx));
  }

  // Click-outside collapses the dropdown — kept simple with a
  // global pointerdown listener rather than wiring a separate
  // overlay element. Re-runs the listener registration whenever
  // ``focused`` flips, so we don't pay the listener cost when the
  // chip isn't active.
  useEffect(() => {
    if (!focused) return;
    function onPointer(e: PointerEvent) {
      if (containerRef.current?.contains(e.target as Node)) return;
      setFocused(false);
    }
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [focused]);

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative flex flex-wrap items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs",
        focused && "ring-2 ring-ring",
        className,
      )}
      onClick={() => inputRef.current?.focus()}
      // An Esc on a suggestion reached with Tab is the list's too (#3157).
      onKeyDown={(e) => {
        if (e.target === inputRef.current) return;
        closePopupOnEscape(e, focused && dropdownItems.length > 0, () =>
          setFocused(false),
        );
      }}
    >
      <Tag className="h-3 w-3 text-muted-foreground" />
      {value.map((chip, idx) => (
        <span
          key={chip}
          className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[11px] text-primary"
        >
          {chip}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              removeAt(idx);
            }}
            className="rounded-full hover:bg-primary/20"
            title={`Remove "${chip}"`}
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      <input
        ref={inputRef}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onFocus={() => setFocused(true)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commit(input);
            return;
          }
          if (e.key === "Escape") {
            // Esc closes the open list and clears the draft; it is this
            // control's Esc, so the dialog around it must not also close
            // (#2720). With nothing open, let it through.
            if (focused && dropdownItems.length > 0) {
              e.preventDefault();
              e.stopPropagation();
              setInput("");
              setFocused(false);
            }
            return;
          }
          // Backspace on an empty textbox deletes the most recent
          // chip — the gmail/slack/discord pattern.
          if (e.key === "Backspace" && !input && value.length > 0) {
            e.preventDefault();
            onChange(value.slice(0, -1));
          }
        }}
        placeholder={value.length === 0 ? placeholder : ""}
        className="min-w-[8rem] flex-1 border-0 bg-transparent px-1 py-0.5 outline-none placeholder:text-muted-foreground/70"
      />
      {focused && dropdownItems.length > 0 && (
        <div className="absolute left-0 right-0 top-full z-20 mt-1 max-h-64 overflow-auto rounded-md border bg-popover py-1 shadow-md">
          {dropdownItems.map((item) => (
            <button
              key={item}
              type="button"
              onMouseDown={(e) => {
                // ``onMouseDown`` (not onClick) so the commit fires
                // before the input loses focus and our outside-click
                // handler collapses the dropdown.
                e.preventDefault();
                commit(item);
                inputRef.current?.focus();
              }}
              className="block w-full px-3 py-1 text-left font-mono text-[11px] hover:bg-accent"
            >
              {item}
            </button>
          ))}
        </div>
      )}
      {focused &&
        dropdownItems.length === 0 &&
        (keysQ.isFetching || valuesQ.isFetching) && (
          <div className="absolute left-0 right-0 top-full z-20 mt-1 rounded-md border bg-popover px-3 py-2 text-[11px] text-muted-foreground shadow-md">
            Loading…
          </div>
        )}
    </div>
  );
}

import { useEffect, useId, useMemo, useRef, useState } from "react";

import { Modal } from "@/components/ui/modal";
import { FormError } from "@/components/ui/form-error";
import { EntityIcon } from "@/components/icons/EntityIcon";
import { countNoun } from "@/lib/count-noun";
import {
  automaticLabel,
  type AutoIcon,
  CORE_ICON_NAMES,
  iconLabel,
  iconValue,
  loadIconMeta,
  searchIcons,
  type IconMetaRow,
} from "@/lib/icons/catalog";

const COLUMNS = 8;
const MAX_RESULTS = 200;

/** The icon picker (#5022). Loaded lazily by ``IconField``: it pulls in the
 *  search metadata, which the main bundle never carries.
 *
 *  Focus stays in the search box and the grid is driven with
 *  ``aria-activedescendant``: arrows move, Enter picks, Escape closes (the
 *  shared Modal). Choice 0 is "Automatic" (clears the explicit icon). */
export default function IconPickerModal({
  current,
  auto,
  onSelect,
  onClose,
}: {
  current: string | null;
  auto?: AutoIcon;
  onSelect: (value: string | null) => void;
  onClose: () => void;
}) {
  const uid = useId();
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<IconMetaRow[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let live = true;
    loadIconMeta()
      .then((r) => live && setRows(r))
      .catch(() => live && setLoadError("The icon list could not be loaded."));
    return () => {
      live = false;
    };
  }, []);

  const searching = query.trim() !== "";
  const names = useMemo(() => {
    if (!searching) return [...CORE_ICON_NAMES];
    return rows ? searchIcons(rows, query) : [];
  }, [searching, rows, query]);
  const shown = names.slice(0, MAX_RESULTS);
  // Index 0 is the Automatic choice; icons follow.
  const total = shown.length + 1;

  useEffect(() => setActive(0), [query]);
  useEffect(() => {
    listRef.current
      ?.querySelector<HTMLElement>(`[id="${uid}-${active}"]`)
      ?.scrollIntoView?.({ block: "nearest" });
  }, [active, uid]);

  const choose = (i: number) =>
    onSelect(i === 0 ? null : iconValue(shown[i - 1]));

  function onKeyDown(e: React.KeyboardEvent) {
    const move = (to: number) => {
      e.preventDefault();
      setActive(Math.max(0, Math.min(total - 1, to)));
    };
    switch (e.key) {
      case "ArrowRight":
        return move(active + 1);
      case "ArrowLeft":
        return move(active - 1);
      case "ArrowDown":
        return move(active === 0 ? 1 : active + COLUMNS);
      case "ArrowUp":
        return move(active <= COLUMNS ? 0 : active - COLUMNS);
      case "Enter":
        e.preventDefault();
        return choose(active);
    }
  }

  const status = loadError
    ? null
    : searching && !rows
      ? "Loading icons…"
      : searching
        ? names.length === 0
          ? "No icons match."
          : names.length > MAX_RESULTS
            ? `${countNoun(names.length, "icon")} match; showing the first ${MAX_RESULTS}. Refine the search to narrow them.`
            : `${countNoun(names.length, "icon")} match.`
        : "Common device icons. Search to find any of the full set.";

  return (
    <Modal title="Choose an icon" onClose={onClose} wide>
      <div className="space-y-3">
        <input
          type="search"
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Search icons — printer, camera, router…"
          aria-label="Search icons"
          role="combobox"
          aria-expanded="true"
          aria-controls={`${uid}-list`}
          aria-activedescendant={`${uid}-${active}`}
          className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <FormError>{loadError}</FormError>
        <div
          ref={listRef}
          id={`${uid}-list`}
          role="listbox"
          aria-label="Icons"
          className="max-h-80 space-y-2 overflow-y-auto"
        >
          <div
            id={`${uid}-0`}
            role="option"
            aria-selected={current === null}
            onClick={() => choose(0)}
            className={`flex cursor-pointer items-center gap-2 rounded border px-3 py-2 text-sm ${
              active === 0 ? "ring-2 ring-ring" : ""
            }`}
          >
            <EntityIcon icon={auto?.icon} decorative size={20} />
            {automaticLabel(auto)}
          </div>
          <div className="grid grid-cols-8 gap-1">
            {shown.map((name, i) => {
              const value = iconValue(name);
              return (
                <div
                  key={name}
                  id={`${uid}-${i + 1}`}
                  role="option"
                  aria-selected={current === value}
                  aria-label={iconLabel(value)}
                  title={iconLabel(value)}
                  onClick={() => choose(i + 1)}
                  className={`flex h-10 cursor-pointer items-center justify-center rounded border ${
                    current === value ? "bg-accent" : "hover:bg-accent/50"
                  } ${active === i + 1 ? "ring-2 ring-ring" : ""}`}
                >
                  <EntityIcon icon={value} decorative size={20} />
                </div>
              );
            })}
          </div>
        </div>
        {status && (
          <p className="text-[11px] text-muted-foreground" aria-live="polite">
            {status}
          </p>
        )}
      </div>
    </Modal>
  );
}

import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, X } from "lucide-react";
import { searchApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { closePopupOnEscape } from "@/components/ui/use-draggable-modal";

/**
 * Debounced IP address picker. Used by the multicast Memberships
 * tab (issue #126 Wave 3) to attach an IPAM IP to a group without
 * requiring the operator to paste a UUID.
 *
 * Wraps the global ``/search`` endpoint with ``types=ip_address``
 * so results stay scoped. The result dropdown shows address +
 * subnet + space breadcrumb so an operator with overlapping
 * spaces (VRFs) can pick the right one.
 */
export function IPAddressPicker({
  value,
  onChange,
  placeholder = "Search by IP / hostname / MAC…",
  disabled = false,
  className,
}: {
  /** Selected IP address id (UUID), or null. */
  value: string | null;
  /**
   * Fires with the picked IP id + a short label for display.
   * The label includes the address + space so the parent can
   * show what's currently picked without re-fetching.
   */
  onChange: (id: string | null, label: string | null) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}) {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // 250 ms debounce — same setting GlobalSearch uses.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  // Click-outside to close the dropdown without losing focus state.
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const q = useQuery({
    queryKey: ["search", "ip_address", debouncedQuery],
    queryFn: () => searchApi.search(debouncedQuery, "ip_address", 25),
    enabled: debouncedQuery.length >= 2,
    staleTime: 30_000,
  });

  const results = (q.data?.results ?? []).filter(
    (r) => r.type === "ip_address",
  );

  return (
    <div ref={containerRef} className={cn("relative", className)}>
      <div className="relative">
        <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <input
          type="text"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) =>
            closePopupOnEscape(e, open && debouncedQuery.length >= 2, () =>
              setOpen(false),
            )
          }
          placeholder={placeholder}
          disabled={disabled}
          className="w-full rounded-md border bg-background py-1.5 pl-7 pr-7 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
        />
        {value && (
          <button
            type="button"
            onClick={() => {
              setQuery("");
              setDebouncedQuery("");
              onChange(null, null);
            }}
            title="Clear selection"
            className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        )}
      </div>

      {open && debouncedQuery.length >= 2 && (
        <div className="absolute left-0 right-0 z-30 mt-1 max-h-72 overflow-auto rounded-md border bg-background shadow-md">
          {q.isFetching && results.length === 0 && (
            <p className="px-3 py-2 text-xs text-muted-foreground">
              Searching…
            </p>
          )}
          {!q.isFetching && results.length === 0 && (
            <p className="px-3 py-2 text-xs text-muted-foreground">
              No IPs match &ldquo;{debouncedQuery}&rdquo;.
            </p>
          )}
          {results.map((r) => {
            const label =
              r.subnet_network && r.space_name
                ? `${r.display} · ${r.subnet_network} · ${r.space_name}`
                : (r.display ?? "?");
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => {
                  onChange(r.id, label);
                  setQuery(label);
                  setOpen(false);
                }}
                className="flex w-full flex-col gap-0.5 border-b px-3 py-2 text-left text-xs hover:bg-accent/50 last:border-b-0"
              >
                <span className="font-mono text-sm">{r.display}</span>
                <span className="text-[11px] text-muted-foreground">
                  {[r.hostname, r.subnet_network, r.space_name]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

import type { ReactNode } from "react";

import { isRefused, listReadErrorMessage } from "@/lib/refusal";
import { cn } from "@/lib/utils";

/**
 * Shown where a list would be when its read failed, in place of the list's
 * empty state (#1343). A refusal is told in the page's muted voice, since it
 * is the reader's permissions and not a fault; any other failure reads as an
 * error. Inline, so it sits in whatever cell, paragraph or panel held the
 * empty-state copy.
 */
export function ListReadError({
  error,
  what,
  className,
}: {
  error: unknown;
  /** What the list holds, as the reader would say it: "users". */
  what: string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        isRefused(error) ? "text-muted-foreground" : "text-destructive",
        className,
      )}
    >
      {listReadErrorMessage(error, what)}
    </span>
  );
}

/**
 * The one way a list page fills the spot where its empty-state copy goes
 * (#1865). `error` is the list query's error: when the read failed, in
 * particular when the server refused the reader (403), it renders
 * {@link ListReadError} in place of `children`, since an empty-state sentence
 * ("No VRFs yet.") over a list the reader may not see is false. With no
 * error it renders `children` untouched, so a list that really is empty
 * still says so.
 *
 * `filtered` (#2616) is for a list that holds rows but hides them all under
 * a search, filter, chip or tag: "No VRFs yet." over a list the filter
 * emptied is false, so it says the filter matches nothing instead, and
 * offers `onClearFilters` when given. The "yet" copy stays for a list that
 * is really empty.
 *
 * Wrap only the empty branch: the caller has already decided there are no
 * rows to show.
 */
export function ListEmpty({
  error,
  what,
  children,
  className,
  filtered = false,
  onClearFilters,
}: {
  error: unknown;
  what: string;
  children: ReactNode;
  className?: string;
  /** A search, filter, chip or tag is active, so an empty result is not an empty list. */
  filtered?: boolean;
  onClearFilters?: () => void;
}) {
  if (error) {
    return <ListReadError error={error} what={what} className={className} />;
  }
  if (filtered) {
    return (
      <span className={className}>
        No {what} match the current search or filter.
        {onClearFilters && (
          <>
            {" "}
            <button
              type="button"
              onClick={onClearFilters}
              className="text-primary underline hover:no-underline"
            >
              Clear filters
            </button>
          </>
        )}
      </span>
    );
  }
  return <>{children}</>;
}

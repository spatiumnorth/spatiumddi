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

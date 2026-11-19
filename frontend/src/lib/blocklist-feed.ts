import { formatAge } from "@/lib/spool-status";

// The list-row sync chip for a feed-sourced blocklist (#2313). The state
// itself comes from the server (`feed_sync_state`, the same classification the
// `dns_blocklist_feed_stale` alert uses); this only turns it into a label.

export interface FeedChipInput {
  feed_sync_state?: string | null;
  last_success_at?: string | null;
  last_synced_at?: string | null;
  last_sync_error?: string | null;
}

export interface FeedChip {
  label: string;
  tone: "red" | "amber" | "grey";
  title: string;
}

/** null = nothing to flag (healthy, or a list with no feed). */
export function feedChip(
  l: FeedChipInput,
  now: number = Date.now(),
): FeedChip | null {
  switch (l.feed_sync_state) {
    case "error": {
      const age = formatAge(l.last_success_at ?? null, now);
      return {
        label: age ? `sync failed · last ok ${age} ago` : "sync failed",
        tone: "red",
        title: l.last_sync_error || "The last refresh failed.",
      };
    }
    case "stale": {
      const age = formatAge(l.last_success_at ?? null, now);
      return {
        label: age ? `stale · ${age} ago` : "stale",
        tone: "amber",
        title:
          "No successful refresh for more than 3x the update interval. Servers keep enforcing the entries the list last had.",
      };
    }
    case "never":
      return {
        label: "never synced",
        tone: "grey",
        title:
          "This feed has never refreshed successfully, so it has no entries from it.",
      };
    default:
      return null;
  }
}

export const FEED_CHIP_CLS: Record<FeedChip["tone"], string> = {
  red: "bg-red-500/15 text-red-600 dark:text-red-400",
  amber: "bg-amber-500/15 text-amber-600",
  grey: "bg-muted text-muted-foreground",
};

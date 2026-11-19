import { AlertTriangle } from "lucide-react";
import type { VersionInfo } from "@/lib/api";

/**
 * The stored result of the last release check, when it failed. Renders
 * nothing when the check is off or the last run succeeded, so the update
 * pill's absence can be told apart from "the check cannot reach GitHub".
 */
function updateCheckErrorText(
  info: Pick<VersionInfo, "latest_check_error" | "release_check_enabled">,
): string | null {
  if (!info.release_check_enabled) return null;
  const err = info.latest_check_error?.trim();
  return err ? err : null;
}

export function UpdateCheckError({
  info,
  compact = false,
}: {
  info: Pick<
    VersionInfo,
    "latest_check_error" | "release_check_enabled" | "latest_checked_at"
  >;
  compact?: boolean;
}) {
  const err = updateCheckErrorText(info);
  if (!err) return null;
  const when = info.latest_checked_at
    ? ` (last attempt ${new Date(info.latest_checked_at).toLocaleString()})`
    : "";
  const title = `Update check failed: ${err}${when}`;
  if (compact) {
    return (
      <span
        role="status"
        title={title}
        className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400"
      >
        <AlertTriangle className="h-3 w-3" />
        check failed
      </span>
    );
  }
  return (
    <p
      role="status"
      className="flex items-start gap-1.5 pb-2 text-xs text-amber-700 dark:text-amber-400"
    >
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span className="min-w-0 break-words">
        Last update check failed: {err}
        {when}
      </span>
    </p>
  );
}

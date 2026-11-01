import { formatApiError } from "@/lib/api";

/**
 * What a failed read means to the page that made it (#1343).
 *
 * A 403 is the server refusing the caller, not reporting on the data: the
 * list behind it can hold rows the caller may not see. A page that renders a
 * refused read's missing data as an empty list tells the reader something
 * false ("Trash is empty." over a trash holding rows). These let a page tell
 * a refusal from an empty answer and from a failure, say which it was, and
 * stop re-asking a read that was refused.
 */

/** The HTTP status a failed API call was answered with; `undefined` when no
 *  response came back (a network error) or the error is not an HTTP one. */
export function apiErrorStatus(err: unknown): number | undefined {
  const status = (err as { response?: { status?: unknown } } | null)?.response
    ?.status;
  return typeof status === "number" ? status : undefined;
}

/** True when the server refused the caller (403). */
export function isRefused(err: unknown): boolean {
  return apiErrorStatus(err) === 403;
}

/** The server's own words for a failed call, or "" when it gave none. Only
 *  a `detail` counts: without one, formatApiError falls back to axios's
 *  "Request failed with status code N", the status code these messages
 *  exist to replace. */
function serverReason(err: unknown): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } } | null)
    ?.response?.data?.detail;
  return detail == null ? "" : formatApiError(err, "");
}

/**
 * The sentence a page shows in place of a list it could not read, never its
 * empty state. `what` names what the list holds, as the reader would say it
 * ("users", "the trash", "webhook subscriptions").
 *
 * A refusal says the reader may not see them, with the server's reason when
 * it gave one ("Superadmin required"). FastAPI's bare default, "Forbidden",
 * says nothing the sentence does not, so it is left out. Any other failure
 * says the list could not be loaded, and why.
 */
export function listReadErrorMessage(err: unknown, what: string): string {
  if (isRefused(err)) {
    const reason = serverReason(err);
    const shown = reason && reason !== "Forbidden" ? ` (${reason})` : "";
    return `You don't have permission to see ${what}${shown}.`;
  }
  return `Couldn't load ${what}: ${formatApiError(err, "the request failed")}`;
}

/**
 * A `refetchInterval` for a polled read that stops polling once the read was
 * refused. A 403 does not heal by asking again, and the server writes a
 * `denied` audit row for every refusal, so a page left open would otherwise
 * add one per interval for as long as it stays open. Any other failure keeps
 * polling, since it may be transient.
 */
export function pollUnlessRefused(
  ms: number,
): (query: { state: { error: Error | null } }) => number | false {
  return (query) => (isRefused(query.state.error) ? false : ms);
}

/**
 * What a failed export or download says, in words (#3255). A 403 says the
 * caller is not permitted, with the server's reason; a 5xx says the export is
 * unavailable; anything else gives the server's own message. Never a bare
 * "Request failed with status code N".
 */
export function exportErrorMessage(err: unknown, what: string): string {
  const reason = serverReason(err);
  if (isRefused(err)) {
    const shown = reason && reason !== "Forbidden" ? ` (${reason})` : "";
    return `You're not permitted to export ${what}${shown}.`;
  }
  const status = apiErrorStatus(err);
  if (status !== undefined && status >= 500) {
    return `Exporting ${what} is unavailable right now${reason ? ` (${reason})` : ""}.`;
  }
  return `Couldn't export ${what}: ${reason || "the request failed"}`;
}

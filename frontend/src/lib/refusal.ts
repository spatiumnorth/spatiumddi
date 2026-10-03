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
    const detail = (err as { response?: { data?: { detail?: unknown } } })
      .response?.data?.detail;
    const reason = detail == null ? "" : formatApiError(err, "");
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
): (query: { state: { error: unknown } }) => number | false {
  return (query) => (isRefused(query.state.error) ? false : ms);
}

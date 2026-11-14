import { useEffect, useRef } from "react";

/**
 * Re-ask for a stored credential once an integration's address is edited
 * (#4135).
 *
 * The API never returns a stored password / token / community, and it refuses
 * an edit that moves the destination (URL, host, port, endpoint) unless the
 * same request supplies the credential again. This hook lets an edit form say
 * so up front instead of on Save: while any destination field differs from the
 * value the row was opened with, ``reask`` is true, so the form clears the
 * credential field, shows ``hint``, marks it required and holds Save until it
 * is filled. Changing the address back flips ``reask`` off and the credential
 * returns to "stored" (``onChange(false)`` clears the field again).
 *
 * ``destination`` is the live form values, ``baseline`` what the row was
 * opened with; both keyed identically. Values compare as text, so a numeric
 * port edited to the same number is not a move. A create form passes
 * ``baseline`` as ``null`` and never re-asks.
 *
 * Usage, per credential::
 *
 *     const reask = useCredentialReask({ host, port }, row && { host: row.host, port: row.port },
 *       () => setSecret(""));
 *     const mustEnter = reask.asks(row?.secret_set);   // stored and address moved
 *     // placeholder: mustEnter ? reask.placeholder : "(stored)"
 *     // Save disabled when mustEnter && !secret.trim()
 *
 * The server's 422 stays the backstop.
 */
export const REASK_HINT = "Re-enter the credential for the new address.";
export const REASK_PLACEHOLDER = "re-enter for the new address";

export interface CredentialReask {
  /** A destination field differs from the value the row was opened with. */
  reask: boolean;
  /** True when the address moved and a credential is stored (so it is required). */
  asks: (stored: boolean | null | undefined) => boolean;
  hint: string;
  placeholder: string;
}

export function useCredentialReask(
  destination: Record<string, unknown>,
  baseline: Record<string, unknown> | null | undefined,
  onChange?: (reask: boolean) => void,
): CredentialReask {
  const reask =
    !!baseline &&
    Object.keys(baseline).some(
      (k) => String(destination[k] ?? "") !== String(baseline[k] ?? ""),
    );

  const prev = useRef(reask);
  const cb = useRef(onChange);
  cb.current = onChange;
  useEffect(() => {
    if (prev.current !== reask) {
      prev.current = reask;
      cb.current?.(reask);
    }
  }, [reask]);

  return {
    reask,
    asks: (stored) => reask && !!stored,
    hint: REASK_HINT,
    placeholder: REASK_PLACEHOLDER,
  };
}

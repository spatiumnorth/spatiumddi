import { useCallback, useState } from "react";

import { ConfirmModal } from "@/components/ui/confirm-modal";

/**
 * Close guard for a dialog that shows a secret exactly once (#3222).
 *
 * Closing such a dialog before the operator has the secret loses it for
 * good: an API token, a webhook signing secret, a TSIG secret, an ephemeral
 * pairing code, a fresh set of recovery codes. So every way out of the
 * dialog (its Done button, the X, Esc) goes through ``requestClose``, which
 * closes straight away once the secret has been taken and otherwise asks
 * first, with "Go back" focused so Enter backs out.
 *
 * "Taken" means one of:
 *   * the dialog's copy button succeeded — the caller calls ``markTaken``
 *     on a ``true`` from ``copyToClipboard`` (a failed copy does not count);
 *   * a masked secret was revealed — the caller calls ``markTaken``;
 *   * the operator copied it by hand — spread ``copyProps`` on the dialog
 *     body, and a Ctrl/⌘+C whose selection holds every one of ``secrets``
 *     counts. Selecting the label next to it does not.
 *
 * Render ``confirm`` next to the dialog. Pass ``active: false`` while the
 * dialog is not (yet) showing a secret, e.g. the form step before the
 * create call returns, so its Cancel closes as it always did.
 */
export function useSecretCloseGuard({
  onClose,
  secrets,
  noun,
  revealable = false,
  active = true,
}: {
  onClose: () => void;
  /** The value(s) shown once; a manual copy counts when it holds all of them. */
  secrets: readonly string[];
  /** What is shown, for the prompt: "token", "secret", "pairing code"… */
  noun: string;
  /** The secret starts masked, so revealing it also counts. Changes the
   *  prompt from "haven't copied" to "haven't copied or revealed". */
  revealable?: boolean;
  active?: boolean;
}) {
  const [taken, setTaken] = useState(false);
  const [asking, setAsking] = useState(false);

  const markTaken = useCallback(() => setTaken(true), []);

  const requestClose = useCallback(() => {
    if (taken || !active) onClose();
    else setAsking(true);
  }, [taken, active, onClose]);

  const onCopy = useCallback(() => {
    const sel = window.getSelection()?.toString() ?? "";
    if (secrets.length > 0 && secrets.every((s) => s && sel.includes(s))) {
      setTaken(true);
    }
  }, [secrets]);

  const verb = revealable ? "copied or revealed" : "copied";
  const confirm = (
    <ConfirmModal
      open={asking}
      title="Close without copying?"
      message={`You haven't ${verb} this ${noun}. It won't be shown again — close anyway?`}
      cancelLabel="Go back"
      confirmLabel="Close without copying"
      tone="destructive"
      autoFocusCancel
      onConfirm={() => {
        setAsking(false);
        onClose();
      }}
      onClose={() => setAsking(false)}
    />
  );

  return { requestClose, markTaken, copyProps: { onCopy }, confirm };
}

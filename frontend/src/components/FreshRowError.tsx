import { Modal } from "@/components/ui/modal";
import { formatApiError } from "@/lib/api";

/**
 * Shown in place of an edit form whose fresh read failed (`useFreshRow`).
 * The form is never seeded from the cached row instead: that row may predate
 * a change made elsewhere, and its Save would write the old values back.
 */
export function FreshRowError({
  title,
  error,
  onRetry,
  onClose,
}: {
  title: string;
  error: unknown;
  onRetry: () => void;
  onClose: () => void;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <p role="alert" className="text-sm text-destructive">
        Couldn't read the current values:{" "}
        {formatApiError(error, "the request failed")}
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onRetry}
          className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
        >
          Retry
        </button>
      </div>
    </Modal>
  );
}

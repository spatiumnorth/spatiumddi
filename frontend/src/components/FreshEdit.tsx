import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { FreshRowError } from "@/components/FreshRowError";
import { refetchRow, useFreshRow } from "@/hooks/useFreshRow";

/**
 * Mounts an Edit dialog on the row read when it opens (#4370), not on the
 * click-time copy the list holds, which another client may have changed since.
 * `queryKeys` are the cached list(s) the row comes from; they are refetched
 * (or pass `load` to read the one row).
 * Renders nothing until the read lands, and a retry-or-cancel box if it fails.
 * The dialog it renders should send only what the operator changed, against
 * the row it was given (`changedFields`).
 */
export function FreshEdit<T extends { id: string }>({
  row,
  queryKeys,
  load,
  title,
  onClose,
  children,
}: {
  row: T;
  queryKeys?: readonly (readonly unknown[])[];
  /** Read the one row directly, for a list that is paged or filtered. */
  load?: () => Promise<T | undefined>;
  title: string;
  onClose: () => void;
  children: (fresh: T) => ReactNode;
}) {
  const qc = useQueryClient();
  const fresh = useFreshRow<T>(row, () =>
    load ? load() : refetchRow<T>(qc, queryKeys ?? [], row.id),
  );
  if (fresh.error)
    return (
      <FreshRowError
        title={title}
        error={fresh.error}
        onRetry={fresh.retry}
        onClose={onClose}
      />
    );
  if (!fresh.ready || !fresh.row) return null;
  return <>{children(fresh.row)}</>;
}

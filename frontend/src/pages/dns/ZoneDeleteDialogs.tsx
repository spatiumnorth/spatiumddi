import { ConfirmDestroyModal } from "./ConfirmDestroyModal";

// Zones are soft-deleted (backend/app/db.py): the default DELETE moves the
// zone and its records to Trash, restorable from Administration → Trash.
// "Permanent" belongs to the Trash page's purge and the superadmin
// ?permanent=true path, not to these dialogs (#1880).
const TRASH_WARNING =
  "The zone and its records move to Trash. You can restore them from Administration → Trash.";

export function DeleteZoneDialog({
  zoneName,
  onConfirm,
  onClose,
  isPending,
  error,
  notice,
}: {
  zoneName: string;
  onConfirm: () => void;
  onClose: () => void;
  isPending?: boolean;
  error?: string | null;
  notice?: string | null;
}) {
  return (
    <ConfirmDestroyModal
      title="Delete DNS Zone"
      description={`Move zone "${zoneName}" and all its records to Trash? The zone stops being served, and can be restored from Administration → Trash.`}
      checkLabel={`I understand "${zoneName}" and all its records will be moved to Trash.`}
      confirmTitle="Move Zone to Trash"
      warning={TRASH_WARNING}
      confirmButtonLabel="Move to Trash"
      onConfirm={onConfirm}
      onClose={onClose}
      isPending={isPending}
      error={error}
      notice={notice}
    />
  );
}

export function BulkDeleteZonesDialog({
  count,
  onConfirm,
  onClose,
  isPending,
  error,
}: {
  count: number;
  onConfirm: () => void;
  onClose: () => void;
  isPending?: boolean;
  error?: string | null;
}) {
  const s = count === 1 ? "" : "s";
  return (
    <ConfirmDestroyModal
      title={`Delete ${count} zone${s}`}
      description={
        <>
          Move the <span className="font-medium">{count}</span> selected zone
          {s} and all their records to Trash? They stop being served, and can be
          restored from Administration → Trash.
        </>
      }
      checkLabel={`I understand ${count} zone${s} and all their records will be moved to Trash.`}
      confirmTitle={`Move ${count} Zone${s} to Trash`}
      warning={TRASH_WARNING}
      confirmButtonLabel="Move to Trash"
      onConfirm={onConfirm}
      onClose={onClose}
      isPending={isPending}
      error={error}
    />
  );
}

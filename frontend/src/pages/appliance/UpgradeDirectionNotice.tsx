/**
 * The amber note under the per-box OS upgrade form when the typed target is
 * not a plain upgrade (#1182, #2068).
 *
 * `same` used to promise "re-write the inactive slot ... and reboot into it".
 * Neither happens: the supervisor does not fire the slot-upgrade trigger when
 * the installed version equals the goal, the heartbeat ingest then drops the
 * goal, and the host runner only stages and never reboots. So the note says
 * nothing will be written, and the form disables its button for that case.
 */
export function UpgradeDirectionNotice({
  direction,
  tag,
  installed,
}: {
  direction: "backward" | "same" | string;
  tag: string;
  installed: string | null | undefined;
}) {
  if (direction !== "backward" && direction !== "same") return null;
  return (
    <p className="rounded-md border border-amber-500/40 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-800 dark:text-amber-300">
      {direction === "backward" ? (
        <>
          <strong>{tag.trim()}</strong> is older than the installed{" "}
          <strong>{installed}</strong>: this is a rollback, not an upgrade. The
          older release boots against a database the newer one may already have
          migrated.
        </>
      ) : (
        <>
          This node already runs <strong>{tag.trim()}</strong>. Nothing will be
          written: the inactive slot is left as it is and the node does not
          reboot. Pick a different release to upgrade it.
        </>
      )}
    </p>
  );
}

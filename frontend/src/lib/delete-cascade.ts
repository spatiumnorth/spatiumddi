// What a delete takes with the row, beyond the row itself (#4143, #4144,
// #4145). The delete confirm dialogs read their "removed with it" lists from
// delete-cascade.json, and backend/tests/test_delete_cascade_copy_4143.py
// walks the SQLAlchemy foreign-key graph from each dialog's root table and
// fails when a table that cascades is neither named there nor listed as
// exempt with a reason. A new child table therefore cannot ship without
// the dialog either naming it or the author saying why it need not.
import registry from "./delete-cascade.json";

export type CascadeDialog = keyof typeof registry.dialogs;

type DialogEntry = {
  includes: readonly string[];
  tables: readonly string[];
  extra: readonly string[];
};

const tablePhrases: Record<string, string> = registry.tables;
const dialogs: Record<string, DialogEntry> = registry.dialogs;

/** "a", "a and b", "a, b and c". */
export function joinList(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** The phrases a dialog names for its own tables, then its extras. */
export function cascadePhrases(dialog: CascadeDialog): string[] {
  const d = dialogs[dialog];
  return [...d.tables.map((t) => tablePhrases[t]), ...d.extra];
}

/** `cascadePhrases` as one list: "OT devices, BACnet/IP devices and ...". */
export function cascadeList(dialog: CascadeDialog): string {
  return joinList(cascadePhrases(dialog));
}

import { lazy, Suspense, useState } from "react";

import { EntityIcon } from "@/components/icons/EntityIcon";
import { useFieldControl } from "@/components/ui/field";
import { iconLabel, type AutoIcon } from "@/lib/icons/catalog";

// The picker (and with it the search metadata) is its own chunk.
const IconPickerModal = lazy(
  () => import("@/components/icons/IconPickerModal"),
);

/** Form control for an icon (#5022): shows the explicit choice, or
 *  "Automatic" with what that currently resolves to, and opens the picker.
 *  Put it inside a shared ``<Field label="Icon">``. ``value`` is the explicit
 *  ``mdi:<name>`` (null = automatic); ``auto`` is what the row would draw
 *  without it (the row's ``effective_icon`` / ``icon_source`` while no
 *  explicit icon is set). */
export function IconField({
  value,
  onChange,
  auto,
  disabled,
}: {
  value: string | null;
  onChange: (value: string | null) => void;
  auto?: AutoIcon;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const control = useFieldControl();
  const shown = value ?? auto?.icon ?? null;
  return (
    <>
      <button
        type="button"
        {...control}
        disabled={disabled}
        onClick={() => setOpen(true)}
        className="inline-flex w-full items-center gap-2 rounded-md border bg-background px-3 py-1.5 text-left text-sm hover:bg-accent disabled:opacity-50"
      >
        <EntityIcon icon={shown} decorative size={20} />
        <span className="flex-1">{value ? iconLabel(value) : "Automatic"}</span>
        <span className="text-xs text-muted-foreground">Change…</span>
      </button>
      {open && (
        <Suspense fallback={null}>
          <IconPickerModal
            current={value}
            auto={auto}
            onSelect={(v) => {
              onChange(v);
              setOpen(false);
            }}
            onClose={() => setOpen(false)}
          />
        </Suspense>
      )}
    </>
  );
}

import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * The one way a dialog or form draws the reason a save was refused (#3821).
 * A plain red `<p>` is not announced: the dialog stays open, focus stays
 * where it was, and a screen reader user hears nothing after pressing Save.
 * `role="alert"` makes the line a live region that is read as it appears, as
 * New Client Class's refusal has been since #3155. Renders nothing for an
 * empty `children`, so callers can pass the error state straight in.
 */
export function FormError({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  if (!children) return null;
  return (
    <p role="alert" className={cn("text-xs text-destructive", className)}>
      {children}
    </p>
  );
}

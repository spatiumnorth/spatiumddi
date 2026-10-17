import * as React from "react";
import * as ContextMenuPrimitive from "@radix-ui/react-context-menu";
import { cn } from "@/lib/utils";

export const ContextMenu = ContextMenuPrimitive.Root;

// Where the open menu was opened, so focus can go back to its row once a dialog
// the menu launched closes (#2051). Recorded on the trigger as the menu opens
// (right-click, the context-menu key, or a touch long-press), together with
// the modal dialogs already open then: only a dialog that appeared AFTER the
// menu opened was launched by it. A menu inside a dialog must not mistake its
// own host dialog for one it opened. Module-level because Radix shows one
// context menu at a time.
let opened: { trigger: HTMLElement; before: Set<Element> } | null = null;

const modalDialogs = () =>
  Array.from(
    document.querySelectorAll<HTMLElement>('[role="dialog"][aria-modal="true"]'),
  );

function recordOpen(trigger: HTMLElement) {
  opened = { trigger, before: new Set(modalDialogs()) };
}

export const ContextMenuTrigger = React.forwardRef<
  React.ElementRef<typeof ContextMenuPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Trigger>
>(({ onContextMenu, onPointerDown, ...props }, ref) => (
  <ContextMenuPrimitive.Trigger
    ref={ref}
    onContextMenu={(e) => {
      recordOpen(e.currentTarget as HTMLElement);
      onContextMenu?.(e);
    }}
    onPointerDown={(e) => {
      // Touch opens on a long-press timer, not a contextmenu event.
      if (e.pointerType !== "mouse") recordOpen(e.currentTarget as HTMLElement);
      onPointerDown?.(e);
    }}
    {...props}
  />
));
ContextMenuTrigger.displayName = "ContextMenuTrigger";

/** Radix returns focus to the trigger when the menu closes. When the chosen
 * item opened a dialog, that runs AFTER the dialog took focus and steals it
 * back to the row behind it (#2051). Skip the restore in that case, and put
 * focus on the row once every dialog the menu launched is gone, unless
 * something (the dialog's own focus return) already placed it. With no new
 * dialog, Radix's restore to the row stands. */
function handleCloseAutoFocus(e: Event) {
  const ctx = opened;
  opened = null;
  if (!ctx) return;
  const launched = () => modalDialogs().filter((d) => !ctx.before.has(d));
  const fresh = launched();
  if (fresh.length === 0) return;
  e.preventDefault();
  const top = fresh[fresh.length - 1];
  if (!fresh.some((d) => d.contains(document.activeElement))) top.focus();
  const obs = new MutationObserver(() => {
    if (launched().length > 0) return;
    obs.disconnect();
    const active = document.activeElement;
    const placed = active && active !== document.body && active.isConnected;
    if (!placed && ctx.trigger.isConnected) ctx.trigger.focus();
  });
  obs.observe(document.body, { childList: true, subtree: true });
}
export const ContextMenuPortal = ContextMenuPrimitive.Portal;
export const ContextMenuGroup = ContextMenuPrimitive.Group;

export const ContextMenuContent = React.forwardRef<
  React.ElementRef<typeof ContextMenuPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Content>
>(({ className, onCloseAutoFocus, ...props }, ref) => (
  <ContextMenuPrimitive.Portal>
    <ContextMenuPrimitive.Content
      ref={ref}
      onCloseAutoFocus={(e) => {
        onCloseAutoFocus?.(e);
        if (!e.defaultPrevented) handleCloseAutoFocus(e);
      }}
      className={cn(
        "z-50 min-w-[11rem] overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md",
        "data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
        className,
      )}
      {...props}
    />
  </ContextMenuPrimitive.Portal>
));
ContextMenuContent.displayName = "ContextMenuContent";

export const ContextMenuItem = React.forwardRef<
  React.ElementRef<typeof ContextMenuPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Item> & {
    destructive?: boolean;
  }
>(({ className, destructive, ...props }, ref) => (
  <ContextMenuPrimitive.Item
    ref={ref}
    className={cn(
      "relative flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-xs outline-none",
      "focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      destructive &&
        "text-destructive focus:bg-destructive/10 focus:text-destructive",
      className,
    )}
    {...props}
  />
));
ContextMenuItem.displayName = "ContextMenuItem";

export const ContextMenuSeparator = React.forwardRef<
  React.ElementRef<typeof ContextMenuPrimitive.Separator>,
  React.ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Separator>
>(({ className, ...props }, ref) => (
  <ContextMenuPrimitive.Separator
    ref={ref}
    className={cn("-mx-1 my-1 h-px bg-border", className)}
    {...props}
  />
));
ContextMenuSeparator.displayName = "ContextMenuSeparator";

export const ContextMenuLabel = React.forwardRef<
  React.ElementRef<typeof ContextMenuPrimitive.Label>,
  React.ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Label>
>(({ className, ...props }, ref) => (
  <ContextMenuPrimitive.Label
    ref={ref}
    className={cn(
      "px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground",
      className,
    )}
    {...props}
  />
));
ContextMenuLabel.displayName = "ContextMenuLabel";

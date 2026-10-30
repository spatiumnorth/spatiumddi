import { useCallback, useEffect, useRef, useState } from "react";
import { Keyboard } from "lucide-react";
import { Modal } from "@/components/ui/modal";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";
import {
  formatCombo,
  isMacPlatform,
  isTypingTarget,
  matchesShortcut,
  SHORTCUT_GROUPS,
  SHOW_SHORTCUTS,
  type Shortcut,
} from "@/lib/shortcuts";

/**
 * `?` keyboard-shortcut help overlay (issue #81).
 *
 * The button and the modal live in one component on purpose: the header
 * needs an affordance (a keyboard-only route to "what are the keyboard
 * shortcuts?" is circular — you'd have to already know the shortcut),
 * and the `?` binding needs a listener. Splitting them would mean
 * lifting `open` into a context or messaging between the two, for a
 * single boolean. Mounted in `Header`, which `AppLayout` always renders,
 * so the binding is live on every page.
 *
 * The list of bindings comes from `lib/shortcuts.ts`, not from this
 * file — see that module for how far the anti-drift guarantee reaches.
 */

function Keys({ shortcut }: { shortcut: Shortcut }) {
  const mac = isMacPlatform();
  return (
    <span className="flex shrink-0 items-center gap-1">
      {shortcut.combos.map((combo, i) => (
        <span key={formatCombo(combo, mac)} className="flex items-center gap-1">
          {i > 0 && (
            <span className="text-[10px] text-muted-foreground">or</span>
          )}
          <kbd className="rounded border border-b-2 bg-muted px-1.5 py-0.5 font-mono text-[11px] font-medium text-foreground">
            {formatCombo(combo, mac)}
          </kbd>
        </span>
      ))}
    </span>
  );
}

export function KeyboardShortcutsHelp() {
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const { enabled } = useFeatureModules();
  const { can } = usePermissions();

  // The keydown listener is bound once, so it can't close over `open`.
  // A ref keeps the current value available without re-binding on every
  // toggle (which would also mean tearing the listener down mid-event).
  const openRef = useRef(open);
  useEffect(() => {
    openRef.current = open;
  }, [open]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // Never steal a printable character from a field being typed in —
      // "?" is a legitimate thing to put in a description.
      if (isTypingTarget(e.target)) return;
      if (!matchesShortcut(e, SHOW_SHORTCUTS)) return;
      // Don't stack on top of another dialog: a reference sheet has no
      // business covering an edit form (Esc would still close only the
      // topmost, #1947). Closing our own overlay is still fine, hence the
      // `openRef` check first.
      if (
        !openRef.current &&
        document.querySelector('[role="dialog"][aria-modal="true"]')
      ) {
        return;
      }
      e.preventDefault();
      setOpen((v) => !v);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // Hide groups whose surface is switched off — no point advertising
  // Copilot bindings when the drawer can't be opened.
  // Hide a binding whose handler stands down for this user (a Viewer's
  // `n` adds no record, #3103), and a group left with none.
  const groups = SHORTCUT_GROUPS.filter((g) => !g.module || enabled(g.module))
    .map((g) => ({
      ...g,
      shortcuts: g.shortcuts.filter(
        (s) =>
          !s.requires ||
          s.requires.resourceTypes.some((t) => can(s.requires!.action, t)),
      ),
    }))
    .filter((g) => g.shortcuts.length > 0);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="Keyboard shortcuts (?)"
        aria-label="Show keyboard shortcuts"
        // Hidden on touch/narrow viewports: the header is already tight
        // there (the Sign out label drops below sm) and an overlay of
        // keyboard bindings is not actionable without a keyboard.
        className="hidden rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground sm:block"
      >
        <Keyboard className="h-4 w-4" />
      </button>

      {open && (
        <Modal title="Keyboard shortcuts" onClose={close} wide>
          <div className="space-y-5">
            {groups.map((group) => (
              <section key={group.id}>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {group.title}
                  {group.context && (
                    <span className="ml-1.5 font-normal normal-case tracking-normal">
                      — {group.context}
                    </span>
                  )}
                </h3>
                <dl className="space-y-1.5">
                  {group.shortcuts.map((s) => (
                    <div
                      key={s.id}
                      className="flex items-baseline gap-3 text-sm"
                    >
                      <dt className="min-w-0 flex-1 text-muted-foreground">
                        {s.description}
                      </dt>
                      <dd>
                        <Keys shortcut={s} />
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
            ))}
          </div>
        </Modal>
      )}
    </>
  );
}

import type { CredentialState } from "@/lib/api";
import {
  credentialChipView,
  type CredentialChipView,
} from "@/lib/credential-chip";

/**
 * Chip for an integration credential that expires (#2138).
 *
 * The state comes from the backend (app/services/integration_credentials.py)
 * so this chip, the Integrations dashboard tab and the IPAM-tab panel cannot
 * disagree. Colouring rules live in `lib/credential-chip.ts`.
 */

const TONE_CLS: Record<CredentialChipView["tone"], string> = {
  red: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  amber: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  muted: "bg-muted text-muted-foreground",
};

export function CredentialChip({
  state,
  daysLeft,
  expiresAt,
  showOk,
  showUnknown,
  onClick,
  className = "",
}: {
  state: CredentialState | null | undefined;
  daysLeft?: number | null;
  expiresAt?: string | null;
  showOk?: boolean;
  showUnknown?: boolean;
  // When set, the chip is a button (e.g. "replace the token").
  onClick?: () => void;
  className?: string;
}) {
  const view = credentialChipView(state, daysLeft, expiresAt, {
    showOk,
    showUnknown,
  });
  if (!view) return null;
  const cls = `inline-flex shrink-0 items-center whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ${TONE_CLS[view.tone]} ${className}`;
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={`${cls} hover:opacity-80`}
        title={`${view.title} Click to replace the token.`}
      >
        {view.label}
      </button>
    );
  }
  return (
    <span className={cls} title={view.title}>
      {view.label}
    </span>
  );
}

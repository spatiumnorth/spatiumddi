import { ReauthFields } from "@/components/ReauthFields";

/**
 * #1355 / #1412 — confirming yourself before handing out something that
 * passes every later step-up: a superadmin, a superadmin's password, or a
 * group / role / grant change that makes someone a superadmin.
 */
export function StepUpSection({
  reason,
  password,
  onPassword,
  totp,
  onTotp,
}: {
  reason: string;
  password: string;
  onPassword: (v: string) => void;
  totp: string;
  onTotp: (v: string) => void;
}) {
  return (
    <div className="rounded-md border bg-amber-500/5 p-3">
      <p className="mb-2 text-xs text-muted-foreground">{reason}</p>
      <ReauthFields
        password={password}
        onPassword={onPassword}
        totp={totp}
        onTotp={onTotp}
      />
    </div>
  );
}

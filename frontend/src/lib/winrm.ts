import type { WinRMSettings } from "@/lib/api";

/** The WinRM settings a Windows DNS / DHCP edit dialog shows. */
export interface WinRMForm {
  port: string;
  transport: "ntlm" | "basic" | "credssp";
  useTls: boolean;
  verifyTls: boolean;
}

/** What a new server's dialog starts from (matches the API's create
 * defaults when the block omits a field). */
export const WINRM_FORM_DEFAULTS: WinRMForm = {
  port: "5985",
  transport: "ntlm",
  useTls: false,
  verifyTls: false,
};

/** Seed the dialog from the settings the server echoes, so it shows what is
 * stored rather than a hard-coded default. */
export function winrmFormFrom(settings?: WinRMSettings | null): WinRMForm {
  if (!settings) return { ...WINRM_FORM_DEFAULTS };
  return {
    port: String(settings.winrm_port),
    transport: settings.transport as WinRMForm["transport"],
    useTls: settings.use_tls,
    verifyTls: settings.verify_tls,
  };
}

export interface WinRMSettingsPayload {
  winrm_port?: number;
  transport?: WinRMForm["transport"];
  use_tls?: boolean;
  verify_tls?: boolean;
}

function toPayload(f: WinRMForm): Required<WinRMSettingsPayload> {
  return {
    winrm_port: parseInt(f.port, 10) || (f.useTls ? 5986 : 5985),
    transport: f.transport,
    use_tls: f.useTls,
    verify_tls: f.verifyTls,
  };
}

/** The settings to send.
 *
 * When stored credentials are being edited (`seed` given), only the settings
 * the operator changed are sent: the API merges a partial block over the
 * stored one, so an untouched setting keeps its stored value and an untouched
 * dialog sends nothing. Without a seed (a new server, or a server with
 * nothing stored) every setting is sent.
 */
export function winrmSettingsPayload(
  current: WinRMForm,
  seed?: WinRMForm,
): WinRMSettingsPayload {
  const now = toPayload(current);
  if (!seed) return now;
  const was = toPayload(seed);
  const out: WinRMSettingsPayload = {};
  for (const k of Object.keys(now) as (keyof typeof now)[]) {
    if (now[k] !== was[k]) (out as Record<string, unknown>)[k] = now[k];
  }
  return out;
}

import { permissionGate, usePermissions } from "@/hooks/usePermissions";

/** The reason on an appliance control the caller may not use (#1342). */
export const NEEDS_APPLIANCE_ADMIN =
  "Requires admin permission on the appliance";

/** Every appliance action (rebooting the host, a pod's Restart / Stop /
 *  Start, maintenance mode, the host firewall, first-boot setup) takes
 *  `admin` on `appliance` (appliance/system.py, containers.py,
 *  firewall.py). Returns #1175's `permissionGate` props for such a
 *  control: nothing when allowed, else disabled with the reason. */
export function useApplianceAdminGate(): {
  disabled?: boolean;
  title?: string;
} {
  return permissionGate(
    usePermissions().can("admin", "appliance"),
    NEEDS_APPLIANCE_ADMIN,
  );
}

/** Raw appliance log text — host log files and pod logs, one-shot or
 *  streamed — takes `admin` on `appliance` (diagnostics.py,
 *  containers.py), because a log line can carry whatever a process
 *  printed. The log panes are hidden rather than drawn and left to 403. */
export function useCanReadApplianceLogs(): boolean {
  return usePermissions().can("admin", "appliance");
}

/** Shown in place of a hidden log pane. */
export const NEEDS_APPLIANCE_ADMIN_FOR_LOGS =
  "Log text requires admin permission on the appliance";

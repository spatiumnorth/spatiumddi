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

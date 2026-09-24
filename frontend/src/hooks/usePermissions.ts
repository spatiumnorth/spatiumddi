import { useQuery } from "@tanstack/react-query";

import { authApi, type PermissionGrant } from "@/lib/api";

// Actions a granted `admin` implies. Mirrors the backend
// `_ADMIN_IMPLIES` frozenset in `app/core/permissions.py`.
const ADMIN_IMPLIES = new Set(["read", "write", "delete", "admin"]);

/** Pure matching predicate — a line-for-line mirror of the backend
 *  `_action_matches` / `_resource_type_matches` / `_resource_id_matches`
 *  helpers in `app/core/permissions.py`. Keep the two paired: any change to
 *  the server semantics must be reflected here (and vice versa) or client
 *  graying-out drifts from what the API actually enforces.
 *
 *  - action: granted `*` matches anything; granted `admin` ⇒
 *    read|write|delete|admin; else exact.
 *  - resource_type: granted `*` matches anything; else exact.
 *  - resource_id: granted `null`/`""`/`"*"` ⇒ any instance; else, when a
 *    requested id is supplied, exact string match; an unscoped request
 *    (`undefined`/`null`) against a scoped grant ⇒ no match.
 */
export function permissionMatch(
  grant: PermissionGrant,
  action: string,
  resourceType: string,
  resourceId?: string | null,
): boolean {
  // _action_matches
  const grantedAction = grant.action;
  const actionOk =
    grantedAction === "*" ||
    grantedAction === action ||
    (grantedAction === "admin" && ADMIN_IMPLIES.has(action));
  if (!actionOk) return false;

  // _resource_type_matches
  const grantedType = grant.resource_type;
  if (grantedType !== "*" && grantedType !== resourceType) return false;

  // _resource_id_matches
  const grantedId = grant.resource_id;
  if (grantedId === null || grantedId === "" || grantedId === "*") return true;
  if (resourceId === undefined || resourceId === null) return false;
  return String(grantedId) === String(resourceId);
}

/** Self-introspection of the calling credential's effective permissions.
 *
 * Single React Query subscription (cached 5 min, mirroring
 * `useFeatureModules`). `can()` answers "may I do this?" by matching the
 * server-returned grant list with the same semantics the API enforces.
 *
 * Fail-closed: while the permission set is still loading (or errored),
 * `can()` returns `false`. This is the safe default for graying-out UI —
 * we never optimistically enable an action the user might not hold. The
 * server is always the real gate; this only drives affordance visibility.
 */
export function usePermissions(): {
  can: (
    action: string,
    resourceType: string,
    resourceId?: string | null,
  ) => boolean;
  isSuperadmin: boolean;
  isLoading: boolean;
} {
  const query = useQuery({
    queryKey: ["my-permissions"],
    queryFn: authApi.myPermissions,
    staleTime: 5 * 60 * 1000,
  });

  const isSuperadmin = query.data?.is_superadmin ?? false;

  function can(
    action: string,
    resourceType: string,
    resourceId?: string | null,
  ): boolean {
    if (isSuperadmin) return true;
    if (!query.data) return false; // fail-closed while loading / errored
    return query.data.grants.some((g) =>
      permissionMatch(g, action, resourceType, resourceId),
    );
  }

  return { can, isSuperadmin, isLoading: query.isLoading };
}

/** Props for a write control whose permission check failed (#1155): it
 *  stays where it is, disabled, with the reason as its tooltip, instead of
 *  opening a form that ends in "Permission denied". Spread it after the
 *  control's own ``title`` so the reason replaces that only while denied.
 *  Pass the same check the server makes for the action behind it. */
export function permissionGate(
  allowed: boolean,
  reason: string,
): { disabled?: boolean; title?: string } {
  return allowed ? {} : { disabled: true, title: reason };
}

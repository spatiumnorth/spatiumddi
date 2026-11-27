import { useQuery } from "@tanstack/react-query";

import { authApi } from "@/lib/api";

/** Whether the signed-in user is a tenant user (#4263): confined by the API
 *  to their tenant's IP spaces. The console uses it only to narrow its
 *  navigation to what they can use; the server enforces the boundary.
 *  ``ready`` is false until the answer is known, so a redirect can wait. */
export function useTenantUserState(): { tenantUser: boolean; ready: boolean } {
  const { data, isLoading } = useQuery({
    queryKey: ["auth-me"],
    queryFn: () => authApi.me(),
    staleTime: 5 * 60 * 1000,
  });
  return { tenantUser: data?.is_tenant_user === true, ready: !isLoading };
}

export function useTenantUser(): boolean {
  return useTenantUserState().tenantUser;
}

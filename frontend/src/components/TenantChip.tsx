import { useQuery } from "@tanstack/react-query";

import { useModuleOn } from "@/hooks/useModuleOn";
import { usePermissions } from "@/hooks/usePermissions";
import { tenantsApi } from "@/lib/api";
import { cn } from "@/lib/utils";

/** The tenant an IP space belongs to (#4263), shown beside the space in the
 *  IPAM tree. Only a superadmin can read the tenant list, and a tenant user's
 *  every space is their own, so the chip renders nothing (and fetches nothing)
 *  for anyone else, and while the Tenants module is off. */
export function TenantChip({
  tenantId,
  className,
}: {
  tenantId: string | null | undefined;
  className?: string;
}) {
  const on = useModuleOn("ipam.tenants");
  const { isSuperadmin } = usePermissions();
  const list = useQuery({
    queryKey: ["tenants"],
    queryFn: () => tenantsApi.list(),
    staleTime: 60_000,
    enabled: on && isSuperadmin && !!tenantId,
  });
  if (!tenantId || !on || !isSuperadmin) return null;
  const t = (list.data ?? []).find((x) => x.id === tenantId);
  if (!t) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border border-violet-500/40 bg-violet-500/10 px-1.5 py-0.5 text-[10px] font-medium text-violet-700 dark:text-violet-300",
        className,
      )}
      title={`Tenant: ${t.name}`}
    >
      {t.name}
    </span>
  );
}

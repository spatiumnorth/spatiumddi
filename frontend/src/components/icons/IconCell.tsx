import { EntityIcon } from "@/components/icons/EntityIcon";
import {
  ICON_SOURCE_LABEL,
  iconLabel,
  type IconSource,
} from "@/lib/icons/catalog";

/** The row icon of the IP address table, the DNS record list and the IP
 *  detail header (#5022). Draws nothing when nothing resolves (no
 *  placeholder), otherwise the icon with its name and where it comes from as
 *  the tooltip; an automatic icon looks the same as an explicit one. */
export function IconCell({
  icon,
  source,
  size = 16,
}: {
  icon: string | null | undefined;
  source?: IconSource | null;
  size?: 16 | 20;
}) {
  if (!icon) return null;
  return (
    <span
      className="inline-flex text-muted-foreground"
      title={`${iconLabel(icon)} (${ICON_SOURCE_LABEL[source ?? "none"]})`}
    >
      <EntityIcon icon={icon} size={size} />
    </span>
  );
}

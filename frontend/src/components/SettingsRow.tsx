import {
  Children,
  cloneElement,
  isValidElement,
  useId,
  type ReactElement,
  type ReactNode,
} from "react";
import { Toggle } from "@/components/ui/toggle";

/** A label + description + control row shared by the appliance settings
 *  sections (NTP / SNMP / LLDP / Syslog / APT / SSH / Resolver).
 *
 *  The label is tied to what it names (#4380):
 *   - a row whose child is one ``<input>`` / ``<select>`` / ``<textarea>`` /
 *     ``<Toggle>`` renders a real ``<label htmlFor>`` and hands the control
 *     the matching ``id``, so clicking the label focuses it and a screen
 *     reader announces "Source mode, combobox";
 *   - any other child (several controls, a wrapper div) is wrapped in
 *     ``role="group"`` labelled by the row title — the nested controls then
 *     carry their own names (own ``<label>`` or ``aria-label``).
 *  The visual layout is unchanged from the per-file ``Field`` this replaced. */
export function SettingsRow({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: ReactNode;
}) {
  const uid = useId();
  const labelId = `${uid}-label`;
  const controlId = `${uid}-control`;

  const only =
    Children.count(children) === 1 ? Children.toArray(children)[0] : null;
  const single =
    isValidElement(only) &&
    (only.type === "input" ||
      only.type === "select" ||
      only.type === "textarea" ||
      only.type === Toggle)
      ? (only as ReactElement<{ id?: string }>)
      : null;

  return (
    <div className="flex items-start justify-between gap-8 py-3">
      <div className="max-w-xl">
        {single ? (
          <label htmlFor={controlId} className="block text-sm font-medium">
            {label}
          </label>
        ) : (
          <div id={labelId} className="text-sm font-medium">
            {label}
          </div>
        )}
        {description && (
          <div className="text-xs text-muted-foreground">{description}</div>
        )}
      </div>
      {single ? (
        <div className="flex-shrink-0">
          {cloneElement(single, { id: controlId })}
        </div>
      ) : (
        <div role="group" aria-labelledby={labelId} className="flex-shrink-0">
          {children}
        </div>
      )}
    </div>
  );
}

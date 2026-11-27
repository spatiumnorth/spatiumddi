import { multiSelectValue } from "@/lib/customFieldValues";

/**
 * Input for a `multi_select` custom field (#4288): one checkbox per option,
 * the value a list of the ticked ones. An empty list is sent as [], which
 * the API reads as "no choice".
 */
export function CustomFieldMultiSelect({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: string[];
  value: unknown;
  onChange: (next: string[]) => void;
}) {
  const picked = multiSelectValue(value);
  return (
    <div
      role="group"
      aria-label={label}
      className="flex flex-wrap gap-x-4 gap-y-1"
    >
      {options.map((opt) => (
        <label key={opt} className="flex items-center gap-1.5 text-sm">
          <input
            type="checkbox"
            className="rounded"
            checked={picked.includes(opt)}
            onChange={(e) =>
              onChange(
                e.target.checked
                  ? [...picked, opt]
                  : picked.filter((p) => p !== opt),
              )
            }
          />
          {opt}
        </label>
      ))}
    </div>
  );
}

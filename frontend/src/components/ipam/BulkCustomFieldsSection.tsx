import type { Dispatch, SetStateAction } from "react";
import { CustomFieldMultiSelect } from "@/components/CustomFieldMultiSelect";
import type { CustomField } from "@/lib/api";

// Bulk-edit "Custom fields (merge)" section shared by the address and subnet
// Bulk edit dialogs (#4304). A field is written only when its own box is
// ticked; a ticked field left empty is sent as null, which the bulk-edit
// APIs read as "remove this key". The dialog builds the payload from
// `optIn` + `values` (see `bulkCustomFieldChanges` in ./bulk-custom-fields).

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ring";

export function BulkCustomFieldsSection({
  definitions,
  enabled,
  onEnabledChange,
  optIn,
  onOptInChange,
  values,
  onValuesChange,
  target,
}: {
  definitions: CustomField[];
  enabled: boolean;
  onEnabledChange: (v: boolean) => void;
  optIn: Record<string, boolean>;
  onOptInChange: Dispatch<SetStateAction<Record<string, boolean>>>;
  values: Record<string, unknown>;
  onValuesChange: Dispatch<SetStateAction<Record<string, unknown>>>;
  /** What the change lands on, e.g. "selected IPs". */
  target: string;
}) {
  if (definitions.length === 0) return null;
  return (
    <div className="rounded-md border p-3 space-y-2">
      <label className="flex items-center gap-2 text-sm font-medium">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onEnabledChange(e.target.checked)}
        />
        Custom fields (merge)
      </label>
      {enabled && (
        <>
          <p className="text-[11px] text-muted-foreground -mt-1">
            Tick the box next to each field you want to change — only ticked
            fields are written to {target}. Leaving a ticked field empty clears
            it on every one of the {target}.
          </p>
          <div className="space-y-3">
            {definitions.map((def) => {
              const checked = !!optIn[def.name];
              const val = values[def.name] ?? "";
              return (
                <div key={def.name} className="space-y-1">
                  <label className="flex items-center gap-2 text-xs font-medium">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) =>
                        onOptInChange((prev) => ({
                          ...prev,
                          [def.name]: e.target.checked,
                        }))
                      }
                    />
                    {def.label}
                  </label>
                  {checked && (
                    <div className="pl-5">
                      {def.description && (
                        <p className="mb-1 text-xs text-muted-foreground">
                          {def.description}
                        </p>
                      )}
                      {def.field_type === "boolean" ? (
                        <input
                          type="checkbox"
                          className="rounded"
                          checked={!!val}
                          onChange={(e) =>
                            onValuesChange((prev) => ({
                              ...prev,
                              [def.name]: e.target.checked,
                            }))
                          }
                        />
                      ) : def.field_type === "multi_select" && def.options ? (
                        <CustomFieldMultiSelect
                          label={def.label}
                          options={def.options}
                          value={val}
                          onChange={(next) =>
                            onValuesChange((prev) => ({
                              ...prev,
                              [def.name]: next,
                            }))
                          }
                        />
                      ) : def.field_type === "select" && def.options ? (
                        <select
                          className={inputCls}
                          value={String(val)}
                          onChange={(e) =>
                            onValuesChange((prev) => ({
                              ...prev,
                              [def.name]: e.target.value,
                            }))
                          }
                        >
                          <option value="">— Clear value —</option>
                          {def.options.map((opt) => (
                            <option key={opt} value={opt}>
                              {opt}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <input
                          className={inputCls}
                          type={
                            def.field_type === "number"
                              ? "number"
                              : def.field_type === "date"
                                ? "date"
                                : def.field_type === "email"
                                  ? "email"
                                  : def.field_type === "url"
                                    ? "url"
                                    : "text"
                          }
                          value={String(val)}
                          onChange={(e) =>
                            onValuesChange((prev) => ({
                              ...prev,
                              [def.name]: e.target.value,
                            }))
                          }
                          placeholder="(empty clears field)"
                        />
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

import { Children, cloneElement, isValidElement, useId } from "react";

const CONTROL_TAGS = new Set(["input", "select", "textarea"]);

type ControlElement = React.ReactElement<{ id?: string }>;

function isControlElement(node: React.ReactNode): node is ControlElement {
  return (
    isValidElement(node) &&
    typeof node.type === "string" &&
    CONTROL_TAGS.has(node.type)
  );
}

/** A visible label that names its control (#1994).
 *
 *  When exactly one of the children is an input / select / textarea, the
 *  label points at it (`htmlFor` + a generated id, or the child's own id),
 *  whatever sits beside it — a `<datalist>`, an inline error line. Those
 *  children render exactly as before, with no wrapper, so the `space-y-1`
 *  spacing between them is unchanged.
 *
 *  Otherwise (a checkbox list, a read-only pill, a wrapping `<label>`, a
 *  conditional block) the children are wrapped in a `role="group"` labelled
 *  by the label, so a search by label still finds exactly one thing. The
 *  wrapper carries `space-y-1` so several children keep their spacing. */
export function Field({
  label,
  hint,
  className,
  children,
}: {
  label: string;
  hint?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}) {
  const uid = useId();
  const controls = Children.toArray(children).filter(isControlElement);
  const control = controls.length === 1 ? controls[0] : null;
  const controlId = control ? (control.props.id ?? uid) : undefined;
  return (
    <div className={className ? `space-y-1 ${className}` : "space-y-1"}>
      <label
        id={control ? undefined : uid}
        htmlFor={controlId}
        className="block text-xs font-medium text-muted-foreground"
      >
        {label}
      </label>
      {control ? (
        Children.map(children, (c) =>
          isControlElement(c) ? cloneElement(c, { id: controlId }) : c,
        )
      ) : (
        <div role="group" aria-labelledby={uid} className="space-y-1">
          {children}
        </div>
      )}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}

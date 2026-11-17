import {
  Children,
  cloneElement,
  createContext,
  isValidElement,
  useContext,
  useEffect,
  useId,
  useMemo,
  useState,
} from "react";

const CONTROL_TAGS = new Set(["input", "select", "textarea"]);

type ControlElement = React.ReactElement<{ id?: string }>;

function isControlElement(node: React.ReactNode): node is ControlElement {
  return (
    isValidElement(node) &&
    typeof node.type === "string" &&
    CONTROL_TAGS.has(node.type)
  );
}

/** What a Field passes to a control that is not one of its direct children
 *  (#4387). `aria-labelledby` is set only when the Field wrapped its children
 *  in a group; the control takes it, so the label names the control and not
 *  only the group around it. */
type FieldControlProps = { "aria-labelledby"?: string };

type FieldContextValue = { props: FieldControlProps; claim: () => () => void };

const FieldContext = createContext<FieldContextValue | null>(null);

/** Props to spread on the real control of a component rendered inside a
 *  `<Field>` (a picker, a select inside a wrapper `<div>`): the label then
 *  names that control, and the Field drops its group, so a search by label
 *  finds the control alone. Empty outside a Field, or when the Field already
 *  points its `htmlFor` at a direct child. A Field's children may also be a
 *  function, which receives the same props. Use it on ONE control per Field;
 *  extra controls (a radio, a second select) keep their own names. */
export function useFieldControl(): FieldControlProps {
  const ctx = useContext(FieldContext);
  const claim = ctx?.claim;
  useEffect(() => claim?.(), [claim]);
  return ctx?.props ?? NONE;
}

const NONE: FieldControlProps = {};

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
 *  wrapper carries `space-y-1` so several children keep their spacing.
 *
 *  The group names itself, but not the control inside it (#4387): the real
 *  control takes `useFieldControl()` (inside a component) or the function
 *  form of `children` (inline), which hand it `aria-labelledby`. */
export function Field({
  label,
  hint,
  className,
  children,
}: {
  label: string;
  hint?: React.ReactNode;
  className?: string;
  children: React.ReactNode | ((control: FieldControlProps) => React.ReactNode);
}) {
  const uid = useId();
  const nodes = typeof children === "function" ? null : children;
  const controls = Children.toArray(nodes).filter(isControlElement);
  const control = controls.length === 1 ? controls[0] : null;
  const controlId = control ? (control.props.id ?? uid) : undefined;
  // A control that took the label has its own name, so the group around it
  // would be a second thing found by the same label.
  const [claims, setClaims] = useState(0);
  const claimed = claims > 0 || typeof children === "function";
  const ctx = useMemo<FieldContextValue>(
    () => ({
      props: { "aria-labelledby": uid },
      claim: () => {
        setClaims((n) => n + 1);
        return () => setClaims((n) => n - 1);
      },
    }),
    [uid],
  );
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
        Children.map(nodes, (c) =>
          isControlElement(c) ? cloneElement(c, { id: controlId }) : c,
        )
      ) : (
        <FieldContext.Provider value={ctx}>
          <div
            role={claimed ? undefined : "group"}
            aria-labelledby={claimed ? undefined : uid}
            className="space-y-1"
          >
            {typeof children === "function" ? children(ctx.props) : children}
          </div>
        </FieldContext.Provider>
      )}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}

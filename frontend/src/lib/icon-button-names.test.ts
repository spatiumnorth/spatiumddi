/**
 * Every icon-only button has an accessible name (#1950).
 *
 * A button whose only content is an icon (a lucide component or an <svg>)
 * and that carries no `aria-label`, `aria-labelledby` or `title` is announced
 * by a screen reader as just "button". This parses every component source
 * with the TypeScript compiler (not a regex, so multi-line JSX and attribute
 * order do not matter) and fails on each such button, naming the file and
 * line, so the next icon-only X / trash / chevron added without a name is
 * caught here instead of by an accessibility audit.
 *
 * What counts as a button: native `<button>`, and the `Button` /
 * `HeaderButton` components, whose children become the native button's
 * content. What counts as an icon: a self-closing capitalised element
 * (`<X />`, `<Trash2 />`) or an `<svg>`. Anything else among the children
 * (text, a lowercase element such as `<span className="sr-only">`, a
 * capitalised element with children of its own, a fragment, a `{…}`
 * expression) is treated as content that may carry a name.
 *
 * An icon chosen in an expression (`{busy ? <Loader2 /> : <X />}`,
 * `{ok && <Check />}`) counts as an icon too. Any other capitalised
 * component that takes a permission-gate spread is scanned as well (a local
 * `IconBtn` wrapper, say): the gate's `title` lands on whatever the wrapper
 * renders it as, so beside one only `aria-label`, `aria-labelledby` or a
 * `label` prop (the wrapper's own name for the action) counts (#3395).
 *
 * Known misses, accepted to keep this a cheap static check rather than a
 * render of every page:
 *   - an icon wrapped in a lowercase element (`<span><X /></span>`) is not
 *     seen;
 *   - a button with a spread (`{...props}`) is assumed named, since the
 *     spread may carry `aria-label`. The exceptions are dnd-kit's
 *     `{...attributes}` / `{...listeners}` (they never carry one) and a permission
 *     gate (`{...permissionGate(...)}`, `{...dhcpGate(...)}`, `{...writeGate}`):
 *     it sets a `title` only while the control is DENIED, so a user who
 *     may press the button gets no name from it (#3160);
 *   - `aria-labelledby` is taken on trust: the id it names is not checked;
 *   - other clickable shapes (`role="button"` on a div, a link drawn as an
 *     icon) are not scanned.
 * A render-based check (testing-library `getByRole("button", { name })`) is
 * what pins a specific button; see `DHCPOptionsEditorRemove.test.tsx`.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const NAMING = new Set(["aria-label", "aria-labelledby", "title"]);
const DURABLE = new Set(["aria-label", "aria-labelledby"]);
// A wrapper component's own action-name prop, which it renders as the name.
const WRAPPER_DURABLE = new Set(["aria-label", "aria-labelledby", "label"]);
const BUTTONS = new Set(["button", "Button", "HeaderButton"]);
// A spread of a permission gate gives a title only while denied (#3160):
// `permissionGate(...)`, `dhcpGate(...)`, `writeGate`. Matched as a whole
// identifier, so a spread that merely contains the letters (`navigateProps`,
// `aggregate`) is still assumed to carry a name.
const GATE_SPREAD = /(?:^|\W)(?:gate|\w*Gate)\b/;
// dnd-kit's `useDraggable` / `useSortable` return `attributes` (role, tabIndex,
// aria-roledescription, aria-describedby) and `listeners` (event handlers).
// Neither carries an aria-label, so a spread of them names nothing (#3395).
const DND_SPREAD = /^(?:attributes|listeners)$/;
const spreadMayName = (a: ts.JsxSpreadAttribute): boolean => {
  const t = a.expression.getText();
  return !GATE_SPREAD.test(t) && !DND_SPREAD.test(t);
};

/**
 * Unnamed icon-only buttons another open change fixes, by file. Each entry
 * must still match at least one offender, so whichever change merges second
 * is told by this test to delete the entry instead of leaving a hole.
 */
const PENDING: Record<string, string> = {};

function sources(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) sources(p, out);
    else if (e.name.endsWith(".tsx") && !e.name.includes(".test.")) out.push(p);
  }
  return out;
}

/** 1-based line numbers of the unnamed icon-only buttons in `code`. */
function unnamedIconButtons(fileName: string, code: string): number[] {
  const sf = ts.createSourceFile(
    fileName,
    code,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const found: number[] = [];
  // `{busy ? <Loader2 /> : <X />}` / `{ok && <Check />}`: an expression
  // whose every rendered branch is an icon.
  const iconOnly = (e: ts.Expression): boolean => {
    if (ts.isParenthesizedExpression(e)) return iconOnly(e.expression);
    if (ts.isConditionalExpression(e))
      return iconOnly(e.whenTrue) && iconOnly(e.whenFalse);
    if (
      ts.isBinaryExpression(e) &&
      e.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
    )
      return iconOnly(e.right);
    if (ts.isJsxSelfClosingElement(e)) {
      const tag = e.tagName.getText();
      return /^[A-Z]/.test(tag) || tag === "svg";
    }
    if (ts.isJsxElement(e)) return e.openingElement.tagName.getText() === "svg";
    return false;
  };
  const visit = (n: ts.Node) => {
    const tag = ts.isJsxElement(n) ? n.openingElement.tagName.getText() : "";
    const props = ts.isJsxElement(n)
      ? n.openingElement.attributes.properties
      : undefined;
    // A permission gate overwrites `title` with the refusal reason while
    // denied, so beside one only a real aria-label / aria-labelledby is a
    // name that survives (#3395).
    const gated = !!props?.some(
      (a) =>
        ts.isJsxSpreadAttribute(a) && GATE_SPREAD.test(a.expression.getText()),
    );
    const wrapper = !BUTTONS.has(tag) && /^[A-Z]/.test(tag) && gated;
    if (ts.isJsxElement(n) && props && (BUTTONS.has(tag) || wrapper)) {
      const naming = wrapper ? WRAPPER_DURABLE : gated ? DURABLE : NAMING;
      const named = props.some(
        (a) =>
          (ts.isJsxSpreadAttribute(a) && spreadMayName(a)) ||
          (ts.isJsxAttribute(a) && naming.has(a.name.getText())),
      );
      let content = false;
      let icon = false;
      for (const c of n.children) {
        if (ts.isJsxText(c)) {
          if (c.text.trim()) content = true;
        } else if (ts.isJsxExpression(c)) {
          if (c.expression && iconOnly(c.expression)) icon = true;
          else if (c.expression) content = true;
        } else if (ts.isJsxSelfClosingElement(c)) {
          const tag = c.tagName.getText();
          if (/^[A-Z]/.test(tag) || tag === "svg") icon = true;
          else content = true;
        } else if (ts.isJsxElement(c)) {
          // <svg>…</svg> is an icon; <Badge>text</Badge> or <span> is content.
          if (c.openingElement.tagName.getText() === "svg") icon = true;
          else content = true;
        } else {
          content = true; // a fragment
        }
      }
      if (!named && icon && !content) {
        found.push(sf.getLineAndCharacterOfPosition(n.getStart()).line + 1);
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

describe("icon-only buttons", () => {
  const offenders = sources(SRC).flatMap((file) => {
    const rel = file.slice(SRC.length + 1);
    return unnamedIconButtons(file, readFileSync(file, "utf8")).map((line) => ({
      rel,
      line,
    }));
  });

  it("all carry an aria-label, aria-labelledby or title", () => {
    expect(
      offenders
        .filter((o) => !(o.rel in PENDING))
        .map((o) => `${o.rel}:${o.line}`),
    ).toEqual([]);
  });

  it("has no stale pending entries", () => {
    const stale = Object.keys(PENDING).filter(
      (f) => !offenders.some((o) => o.rel === f),
    );
    expect(stale).toEqual([]);
  });

  // The scanner on fixtures: a guard that finds nothing looks exactly like
  // one that passed.
  it.each([
    [
      "an X icon",
      "<button onClick={f}>\n  <X className='h-4 w-4' />\n</button>",
    ],
    ["an <svg>", "<button><svg><path d='M0 0' /></svg></button>"],
    ["a Button component", "<Button variant='ghost'><Trash2 /></Button>"],
    [
      "only a permission-gate spread",
      "<button {...permissionGate(ok, why)}><Pencil /></button>",
    ],
    [
      "only a gate identifier spread",
      "<button onClick={f} {...writeGate}><Trash2 /></button>",
    ],
    [
      "a title plus a gate spread (the gate replaces the title)",
      "<button title='Edit' {...superadminGate}><Pencil /></button>",
    ],
    [
      "an icon chosen in an expression, title plus gate",
      "<button title='Disable' {...adminGate}>{on ? <PowerOff /> : <Check />}</button>",
    ],
    [
      "a wrapper component given a title and a gate",
      "<IconBtn title='Edit' onClick={f} {...writeGate}><Pencil /></IconBtn>",
    ],
    [
      "dnd-kit attributes/listeners spreads (they carry no name)",
      "<button {...listeners} {...attributes} title='Drag' {...writeGate}><GripVertical /></button>",
    ],
    ["an icon behind &&", "<button>{busy && <Loader2 />}</button>"],
    ["aria-hidden but no name", "<button aria-hidden='true'><X /></button>"],
  ])("flags an unnamed button holding %s", (_, jsx) => {
    expect(unnamedIconButtons("f.tsx", `const a = (${jsx});`)).toEqual([1]);
  });

  it.each([
    ["aria-label", "<button aria-label='Close'><X /></button>"],
    [
      "title",
      "<button\n  title='Close'\n  type='button'\n>\n  <X />\n</button>",
    ],
    ["aria-labelledby", "<button aria-labelledby='t'><X /></button>"],
    ["visible text", "<button><Plus /> Add child</button>"],
    [
      "sr-only text",
      "<button><X /><span className='sr-only'>Close</span></button>",
    ],
    ["a text expression", "<button><X />{label}</button>"],
    ["a spread", "<button {...props}><X /></button>"],
    [
      "a spread whose name only contains 'gate'",
      "<button {...navigateProps}><X /></button>",
    ],
    [
      "a name plus a gate spread",
      "<button aria-label='Edit x' {...permissionGate(ok, why)}><Pencil /></button>",
    ],
    ["a component with text", "<button><Kbd>Esc</Kbd></button>"],
    [
      "a wrapper's label prop beside a gate",
      "<IconBtn label='Edit' onClick={f} {...writeGate}><Pencil /></IconBtn>",
    ],
    [
      "a wrapper with visible text beside a gate",
      "<ActionButton title='Restart' {...gate}>Restart</ActionButton>",
    ],
    [
      "a title on an ungated button whose icon is chosen in an expression",
      "<button title='Sync'>{busy ? <Loader2 /> : <RefreshCw />}</button>",
    ],
  ])("passes a button named by %s", (_, jsx) => {
    expect(unnamedIconButtons("f.tsx", `const a = (${jsx});`)).toEqual([]);
  });
});

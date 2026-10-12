/**
 * @vitest-environment jsdom
 *
 * IPAM's delete confirmations say what the delete does (#1398; #502's
 * class, after #1152).
 *
 * Every delete of an IP space, block or subnet the console sends is a soft
 * delete: the object and what it holds go to Trash as one batch and can be
 * restored for 30 days (operations_risky.py `_apply_delete_space` /
 * `_apply_delete_block` / `_apply_delete_subnet`; the console never sends
 * `permanent=true` for them). #1152 fixed Edit subnet's Danger zone, but its
 * siblings still called the same delete permanent: IPAM's shared two-step
 * confirm ("Confirm Permanent Deletion", "This action cannot be undone.",
 * "Delete permanently") behind the tree's Delete… and both bulk deletes,
 * the tree's check labels, the block view's "Blocks are not restorable from
 * Trash", and Edit Space's and Edit Block's Danger zones and steps — which
 * also promised "a typed confirm in the next step" that is a checkbox.
 *
 * Only an IP address can be deleted for good from IPAM (its purge, the
 * orphan purge, the bulk purge option); their words stay, named below.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { IPSpace } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
const answers: Record<string, Record<string, Answer>> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { ConfirmDestroyModal, EditSpaceModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

/** Words that call a delete permanent. */
const PERMANENT = /permanent|cannot be undone|not restorable|irreversible/i;
/** Words that say the object can be restored (the ddi-pg check's reading). */
const SAYS_RESTORABLE =
  /(?<!\bnot )\b(?:can be restored|restorable|restore (?:it|them)\b)/i;

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const words = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ");
const topDialog = () => screen.getAllByRole("dialog").at(-1)!;
/** The dialog's confirming button: its last one that is not Cancel. */
const confirmButton = (dialog: HTMLElement) =>
  within(dialog)
    .getAllByRole("button")
    .filter((b) => !/^(Cancel|Close)/.test(b.textContent ?? ""))
    .at(-1) as HTMLButtonElement;

describe("IPAM delete confirmations", () => {
  it("Edit Space → Danger zone: says the space goes to Trash, and sends the Trash delete", async () => {
    const deleteSpace = vi.fn(() => Promise.resolve({}));
    answers.ipamApi = { deleteSpace };
    const space = { id: "sp-1", name: "retiring-space" } as IPSpace;
    open(
      <EditSpaceModal space={space} onClose={() => {}} onDeleted={() => {}} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Danger zone" }));
    const danger = words(topDialog());
    fireEvent.click(
      screen.getByRole("button", { name: /^Delete this IP space/ }),
    );
    let said = `${danger} ${words(topDialog())}`;
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    const last = topDialog();
    said += ` ${words(last)}`;
    if (/\btyped\b/i.test(danger)) {
      expect(
        within(last).queryByRole("textbox"),
        "the Danger zone promises a typed confirm in the next step",
      ).not.toBeNull();
    }
    fireEvent.click(within(last).getByRole("checkbox"));
    const button = confirmButton(last);
    await waitFor(() => expect(button.disabled).toBe(false));
    fireEvent.click(button);

    // The delete the dialog sends is the soft one: the id alone, no
    // `permanent`. A console that purged would make "permanent" true.
    await waitFor(() => expect(deleteSpace).toHaveBeenCalledWith("sp-1"));
    expect(
      said.match(PERMANENT)?.[0] ?? null,
      `the dialog calls a Trash delete permanent: "${said}"`,
    ).toBeNull();
    expect(
      /\bTrash\b/.test(said) && SAYS_RESTORABLE.test(said),
      `the dialog never says the space goes to Trash and can be restored: "${said}"`,
    ).toBe(true);
  });

  it("the shared two-step confirm does not call a Trash delete permanent", async () => {
    const onConfirm = vi.fn();
    open(
      <ConfirmDestroyModal
        title="Delete Subnet"
        description="Delete subnet 10.231.12.0/24?"
        checkLabel="I understand 10.231.12.0/24 and its contents will be moved to Trash."
        onConfirm={onConfirm}
        onClose={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const last = topDialog();
    // The step's own words: its title, its warning, its button.
    const own = `${last.getAttribute("aria-label") ?? ""} ${words(last)}`;
    fireEvent.click(within(last).getByRole("checkbox"));
    fireEvent.click(confirmButton(last));

    expect(onConfirm).toHaveBeenCalled();
    expect(
      own.match(PERMANENT)?.[0] ?? null,
      `every caller deletes into Trash (the tree's Delete…, both bulk ` +
        `deletes), but the confirm step says: "${own}"`,
    ).toBeNull();
    expect(
      /\bTrash\b/.test(own) && SAYS_RESTORABLE.test(own),
      `the confirm step never says the delete can be restored from Trash: "${own}"`,
    ).toBe(true);
  });

  it("calls nothing in IPAM permanent but the deletes that are", () => {
    // The only IPAM deletes that do not go to Trash are an IP address's:
    // its purge (DELETE /ipam/addresses/{id}?permanent=true), the orphan
    // purge, the bulk purge option, Clean Orphans, and the DNS sync's
    // stale records. Each phrase they use, and why it is true.
    const ALLOWED = new Map([
      ["Permanently delete", "address purge: icon title, message, bulk"],
      ["Permanently Delete", "the orphan purge's title"],
      ["? This cannot be undone.", "after an address purge's question"],
      [
        "Auto-generated records that no longer have a live IPAM address. Selecting will permanently delete them and push the delete to BIND.",
        "stale DNS records are deleted from the database and the server",
      ],
      ["permanently removed", "Clean Orphans deletes orphan address rows"],
      [
        "Permanently delete instead of soft-delete",
        "the bulk address delete's own purge option",
      ],
      [
        ", greyed out in the list, and excluded from next-free allocation. DNS and DHCP cascades still run. You can restore or permanently delete it later from the orphans view.",
        "the orphan option: a purge is possible later",
      ],
      ["Delete Permanently (irreversible)", "the address purge option"],
      ["Delete Permanently", "the address purge's button"],
    ]);
    // jsdom gives this module an http: URL, so the file is found from here.
    const file = join(__dirname, "IPAMPage.tsx");
    const sf = ts.createSourceFile(
      file,
      readFileSync(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    );
    const said: string[] = [];
    const seen = new Set<string>();
    const visit = (node: ts.Node): void => {
      if (
        ts.isStringLiteral(node) ||
        ts.isNoSubstitutionTemplateLiteral(node) ||
        ts.isTemplateHead(node) ||
        ts.isTemplateMiddle(node) ||
        ts.isTemplateTail(node) ||
        ts.isJsxText(node)
      ) {
        const text = node.text.replace(/\s+/g, " ").trim();
        if (PERMANENT.test(text)) {
          if (ALLOWED.has(text)) seen.add(text);
          else {
            const line = sf.getLineAndCharacterOfPosition(node.getStart());
            said.push(`IPAMPage.tsx:${line.line + 1}: ${text}`);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
    expect(
      said,
      "IPAM copy calling a delete permanent, where the delete goes to Trash " +
        "and can be restored (an address purge is the only IPAM delete for " +
        "good: add its words to ALLOWED with the reason)",
    ).toEqual([]);
    expect(
      [...ALLOWED.keys()].filter((t) => !seen.has(t)),
      "ALLOWED entries no copy carries any more: remove them",
    ).toEqual([]);
  });
});

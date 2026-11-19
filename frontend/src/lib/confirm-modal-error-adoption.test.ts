// Guard for #4358 (the class #4353 / #4354 started): a ConfirmModal whose
// mutation is refused must say why inside the open dialog, through its `error`
// prop (an announced role="alert" line) or `passwordError`. A confirm that
// passes neither reads as a press that did nothing, because the page behind
// an aria-modal dialog is inert and nothing there is announced.
//
// A source scan, a heuristic: every <ConfirmModal> element must carry one of
// the two props at its own top level, unless its file is listed in ALLOWED
// with the reason the refusal is shown some other way. The list is exact
// (stale entries fail too), so it only shrinks.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

const ERROR_PROP = /(?:^|\s)(?:error|passwordError)=/;

// file (relative to src/) -> how many ConfirmModals it may leave without the
// prop, and why that is safe.
const ALLOWED: Record<string, { count: number; why: string }> = {
  "hooks/useSecretCloseGuard.tsx": {
    count: 1,
    why: "no mutation: Close without copying only closes the local dialog",
  },
  "components/SSHSection.tsx": {
    count: 2,
    why: "closes at the press; a refused re-save is the form's role=alert 'Failed to save' line",
  },
  "pages/admin/CutoverPage.tsx": {
    count: 2,
    why: "Cut over / Roll back close at the press; the refusal and its blockers land in the page's role=alert ErrorBanner",
  },
  "pages/admin/NetBoxImportPage.tsx": {
    count: 1,
    why: "the commit runs in the page's committing phase; a refusal lands in its role=alert banner",
  },
  "pages/admin/SupportBundleSection.tsx": {
    count: 1,
    why: "closes at the press; a refusal lands in the section's FormError",
  },
  "pages/appliance/ContainersTab.tsx": {
    count: 1,
    why: "closes at the press; a refused restart lands in the tab's FormError",
  },
  "pages/appliance/FleetTab.tsx": {
    count: 1,
    why: "schema-refusal override: re-runs the refused slot action, whose refusal is the card's role=alert slot error",
  },
  "pages/appliance/UpgradeImagesTable.tsx": {
    count: 1,
    why: "a bulk of per-image deletes, each outcome (refused, missing, failed) reported in the table's results",
  },
  "pages/network/DeviceFormModal.tsx": {
    count: 1,
    why: "Save and test closes at the press; a failure is the form's role=alert test-result banner",
  },
  ...Object.fromEntries(
    [
      "CertificatesPage",
      "CircuitsPage",
      "CustomersPage",
      "MulticastDomainsPage",
      "MulticastGroupsPage",
      "OverlaysPage",
      "ProvidersPage",
      "ServicesPage",
      "SitesPage",
    ].map((p) => [
      `pages/network/${p}.tsx`,
      {
        count: 1,
        why: "deletes close at the press and the page draws the refusal as its role=alert deleteError",
      },
    ]),
  ),
};

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? files(join(dir, e.name))
      : e.name.endsWith(".tsx") && !e.name.includes(".test.")
        ? [join(dir, e.name)]
        : [],
  );
}

/** Count `<ConfirmModal ...>` elements with neither `error=` nor
 *  `passwordError=` among their own props (a prop buried inside another
 *  prop's `{...}` expression does not count). */
export function confirmModalsWithoutError(source: string): number {
  let missing = 0;
  for (const m of source.matchAll(/<ConfirmModal\b/g)) {
    let i = (m.index ?? 0) + m[0].length;
    let depth = 0;
    let own = "";
    for (; i < source.length; i++) {
      const c = source[i];
      if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (depth === 0) {
        if (c === "/" && source[i + 1] === ">") break;
        own += c;
      }
    }
    if (!ERROR_PROP.test(own)) missing++;
  }
  return missing;
}

describe("confirm dialogs show a refusal (#4358)", () => {
  it("detects a confirm with no error prop", () => {
    const bare = `<ConfirmModal open title="t" onConfirm={() => m.mutate()} onClose={c} />`;
    expect(confirmModalsWithoutError(bare)).toBe(1);
    expect(
      confirmModalsWithoutError(
        bare.replace("open ", "open error={e ? 'x' : null} "),
      ),
    ).toBe(0);
    expect(
      confirmModalsWithoutError(
        bare.replace("open ", "open passwordError={p} "),
      ),
    ).toBe(0);
  });

  it("ignores an error= buried in another prop's expression", () => {
    const src = `<ConfirmModal open message={<Foo error={e} />} onConfirm={() => m.mutate()} onClose={c} />`;
    expect(confirmModalsWithoutError(src)).toBe(1);
  });

  it("every ConfirmModal passes error, or is listed with its reason", () => {
    const found: Record<string, number> = {};
    for (const f of files(SRC)) {
      const n = confirmModalsWithoutError(readFileSync(f, "utf8"));
      if (n) found[relative(SRC, f)] = n;
    }
    const expected = Object.fromEntries(
      Object.entries(ALLOWED).map(([k, v]) => [k, v.count]),
    );
    expect(
      found,
      "pass error={m.error ? formatApiError(m.error, '…') : null} and m.reset() in onClose to the ConfirmModal, as #4357 does; only a confirm whose refusal is announced elsewhere belongs in ALLOWED",
    ).toEqual(expected);
  });
});

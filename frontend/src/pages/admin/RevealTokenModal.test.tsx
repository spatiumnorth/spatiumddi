/**
 * @vitest-environment jsdom
 *
 * The token reveal dialog keeps the raw token out of the masked view.
 *
 * While masked, the dialog shows bullets; the token must not sit in any
 * attribute either — a `title` would surface it as a hover tooltip and as the
 * element's accessible description. Only the revealed view and the copy
 * action carry it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import type { ApiTokenCreated } from "@/lib/api";
import { RevealTokenModal } from "./ApiTokensPage";

const RAW = "sddi_maskprobe_7f3c9a1e5b2d4f6081a2b3c4d5e6f708";

const TOKEN = {
  id: "tok-1",
  name: "ci-runner",
  prefix: RAW.slice(0, 10),
  token: RAW,
} as unknown as ApiTokenCreated;

afterEach(cleanup);

function renderModal() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <RevealTokenModal token={TOKEN} onClose={vi.fn()} />
    </QueryClientProvider>,
  );
}

/** Every attribute value and text node in the document that names the token. */
function placesCarryingToken(): string[] {
  const hits: string[] = [];
  for (const el of Array.from(document.body.querySelectorAll("*"))) {
    for (const attr of Array.from(el.attributes)) {
      if (attr.value.includes(RAW)) {
        hits.push(`<${el.tagName.toLowerCase()} ${attr.name}>`);
      }
    }
  }
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if ((n.nodeValue ?? "").includes(RAW)) hits.push("#text");
  }
  return hits;
}

describe("RevealTokenModal", () => {
  it("names the token nowhere in the DOM while masked", () => {
    renderModal();
    expect(placesCarryingToken()).toEqual([]);
    expect(screen.queryByTitle(RAW)).toBeNull();
    expect(screen.queryByText(RAW)).toBeNull();
  });

  it("shows the token once revealed, and hides it again", () => {
    renderModal();
    fireEvent.click(screen.getByTitle("Reveal"));
    expect(screen.getByText(RAW)).toBeTruthy();

    fireEvent.click(screen.getByTitle("Hide"));
    expect(placesCarryingToken()).toEqual([]);
  });
});

/**
 * @vitest-environment jsdom
 *
 * The UniFi page says when SpatiumDDI writes to a controller (#1396).
 *
 * The page said "Read-only integration. … SpatiumDDI never writes to
 * UniFi.", and its setup guide "SpatiumDDI never writes back, so a read-only
 * role is the correct choice". The controllers it lists are also Active
 * block sync's UniFi targets: each carries its own `block_sync_enabled`
 * switch and write credentials (models/unifi.py), and an armed one is
 * pushed client blocks (L2 quarantine; block_sync/router.py `arm_unifi`).
 * With block sync on, the absolute is untrue of the page's own controllers,
 * and the Features catalog says the opposite. The mirror itself only reads:
 * the page must say that, and say when SpatiumDDI does write.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  // Every API object answers nothing (a pending request) except the
  // controller list, which is empty: the page's own words are under test.
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
                : name === "unifiApi" && method === "listControllers"
                  ? async () => []
                  : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { UnifiPage } = await import("./UnifiPage");

afterEach(cleanup);

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/unifi"]}>
        <UnifiPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The sentences of a block of copy, one space between words. */
function sentences(el: Element): string[] {
  return (el.textContent ?? "")
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+/)
    .filter(Boolean);
}

const NEVER_WRITES = /\bnever (?:writes?|pushes|changes)\b/i;
/** A sentence that says block sync writes to a controller. */
const SAYS_BLOCK_SYNC_WRITES = (s: string) =>
  /\bblock sync\b/i.test(s) && /\b(?:writes?|push(?:es)?)\b/i.test(s);

describe("UniFi page: what SpatiumDDI writes", () => {
  it("does not say SpatiumDDI never writes to UniFi, and says when it does", async () => {
    show();
    // The page's description under its title.
    const header = sentences(await screen.findByText(/mirrored into IPAM/));

    expect(
      header.filter((s) => NEVER_WRITES.test(s)),
      "the page says SpatiumDDI never writes to UniFi, while Active block " +
        "sync pushes client blocks to the controllers it lists",
    ).toEqual([]);
    expect(
      header.some(SAYS_BLOCK_SYNC_WRITES),
      `the page never says when SpatiumDDI writes to a controller: ${header.join(" ")}`,
    ).toBe(true);
  });

  it("the setup guide's read-only advice is for the mirror's key, not block sync", async () => {
    show();
    // The header's Add Controller (the empty list offers a second one).
    fireEvent.click(
      (await screen.findAllByRole("button", { name: /Add Controller/ }))[0],
    );
    // A new controller's dialog opens with its setup guide shown.
    const guide = await screen.findByText(/Generate a UniFi Network API key/);
    const said = sentences(guide);

    expect(
      said.filter((s) => NEVER_WRITES.test(s)),
      "the setup guide says SpatiumDDI never writes back",
    ).toEqual([]);
    expect(
      said.some(SAYS_BLOCK_SYNC_WRITES),
      `the setup guide does not say block sync writes with its own credentials: ${said.join(" ")}`,
    ).toBe(true);
  });
});

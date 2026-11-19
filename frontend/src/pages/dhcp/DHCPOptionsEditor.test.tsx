/**
 * @vitest-environment jsdom
 *
 * The custom-option search box keeps every digit of a typed code (#1685).
 * Each keystroke used to set the row's code, and an effect then rewrote the
 * box to "<code> —", so "43" became "4 —3" and option 4. The typed code is
 * now committed on blur / Enter (or by a pick), never per keystroke.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { DHCPOption } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listOptionCodes: () =>
      Promise.resolve([
        { code: 4, name: "time-servers", kind: "ip", description: "Time" },
        {
          code: 43,
          name: "vendor-encapsulated-options",
          kind: "string",
          description: "Vendor specific",
        },
        {
          code: 60,
          name: "vendor-class-identifier",
          kind: "string",
          description: "Vendor class",
        },
      ]),
  },
}));

import { DHCPOptionsEditor } from "./DHCPOptionsEditor";

let latest: DHCPOption[] = [];

function Harness({ initial }: { initial: DHCPOption[] }) {
  const [v, setV] = useState<DHCPOption[]>(initial);
  latest = v;
  return <DHCPOptionsEditor value={v} onChange={setV} />;
}

async function setup(initial: DHCPOption[] = [{ code: 0, value: "" }]) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Harness initial={initial} />
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByText(/Custom options/));
  const boxes = (await screen.findAllByPlaceholderText(
    "Search code or name…",
  )) as HTMLInputElement[];
  return boxes;
}

function typeKeys(box: HTMLInputElement, text: string) {
  for (const ch of text) {
    fireEvent.change(box, { target: { value: box.value + ch } });
  }
}

afterEach(cleanup);

describe("custom option search box", () => {
  it("keeps both digits when typing 43 key by key, and commits on blur", async () => {
    const [box] = await setup();
    typeKeys(box, "43");
    expect(box.value).toBe("43");
    expect(await screen.findByText("vendor-encapsulated-options")).toBeTruthy();
    fireEvent.blur(box);
    expect(latest).toHaveLength(1);
    expect(latest[0].code).toBe(43);
    expect(latest[0].name).toBe("vendor-encapsulated-options");
    expect(box.value).toBe("43 — vendor-encapsulated-options");
  });

  it("does not turn the row into a standard option on the way to a longer code", async () => {
    // 6 is DNS Servers, a standard field: committing it per keystroke moved
    // the row out of the custom list before the 0 of 60 could be typed.
    const [box] = await setup();
    typeKeys(box, "60");
    expect(box.value).toBe("60");
    expect(screen.getAllByPlaceholderText("Search code or name…")).toHaveLength(
      1,
    );
    fireEvent.blur(box);
    expect(latest.map((o) => o.code)).toEqual([60]);
  });

  it("Enter commits the typed code", async () => {
    const [box] = await setup();
    typeKeys(box, "43");
    fireEvent.keyDown(box, { key: "Enter" });
    expect(latest[0].code).toBe(43);
  });

  it("a catalogue pick after a partial code takes the picked code", async () => {
    const [box] = await setup();
    fireEvent.focus(box);
    typeKeys(box, "6");
    const option = await screen.findByText("vendor-class-identifier");
    fireEvent.mouseDown(option);
    fireEvent.click(option);
    expect(latest.map((o) => o.code)).toEqual([60]);
    expect(latest[0].name).toBe("vendor-class-identifier");
  });

  it("a typed code replaces the previous code's name", async () => {
    const [box] = await setup([
      { code: 43, name: "vendor-encapsulated-options", value: "x" },
    ]);
    fireEvent.change(box, { target: { value: "199" } });
    fireEvent.blur(box);
    expect(latest[0].code).toBe(199);
    expect(latest[0].name).toBeUndefined();
    expect(latest[0].value).toBe("x");
  });

  it("deleting a row with half-typed text removes that row only", async () => {
    const [box] = await setup([
      { code: 43, name: "vendor-encapsulated-options", value: "a" },
      { code: 43, name: "vendor-encapsulated-options", value: "b" },
    ]);
    fireEvent.change(box, { target: { value: "6" } });
    const remove = screen
      .getAllByRole("button")
      .filter((b) => b.querySelector("svg.lucide-x") !== null)[0];
    fireEvent.mouseDown(remove);
    fireEvent.click(remove);
    expect(latest).toEqual([
      { code: 43, name: "vendor-encapsulated-options", value: "b" },
    ]);
    // The surviving row is shown as itself, not with the deleted row's text.
    const [left] = screen.getAllByPlaceholderText(
      "Search code or name…",
    ) as HTMLInputElement[];
    expect(left.value).toBe("43 — vendor-encapsulated-options");
  });
});

/**
 * @vitest-environment jsdom
 *
 * An edit in a custom option row changes that row only (#3508). The editor
 * found the row to replace by comparing contents (code and value), and two
 * blank rows are both `{ code: 0, value: "" }`: a pick, a typed code or a
 * value in the second of two blank rows was written into the first. A row
 * is now found by its place in the list.
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
        {
          code: 2,
          name: "time-offset",
          kind: "int32",
          description: "Offset from UTC",
        },
        {
          code: 43,
          name: "vendor-encapsulated-options",
          kind: "string",
          description: "Vendor specific",
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

function open(initial: DHCPOption[]) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Harness initial={initial} />
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: /Custom options/ }));
}

function searchBoxes() {
  return screen.getAllByPlaceholderText(
    "Search code or name…",
  ) as HTMLInputElement[];
}

function valueBoxes() {
  return screen.getAllByPlaceholderText("value") as HTMLInputElement[];
}

async function pickTimeOffset(box: HTMLInputElement) {
  fireEvent.focus(box);
  fireEvent.change(box, { target: { value: "time" } });
  const suggestion = await screen.findByText("time-offset");
  fireEvent.mouseDown(suggestion);
  fireEvent.click(suggestion);
}

afterEach(cleanup);

describe("two custom option rows that hold the same contents", () => {
  it("a pick in the second of two blank rows sets the second row only", async () => {
    open([]);
    const add = screen.getByRole("button", { name: /Add custom option/ });
    fireEvent.click(add);
    fireEvent.click(add);
    expect(searchBoxes()).toHaveLength(2);

    await pickTimeOffset(searchBoxes()[1]);
    expect(latest).toEqual([
      { code: 0, value: "" },
      { code: 2, name: "time-offset", value: "" },
    ]);
    const [first, second] = searchBoxes();
    expect(first.value).toBe("");
    // The box reads "<code> <em dash> <name>".
    expect(second.value).toBe("2 \u2014 time-offset");

    // Tab out of the second row: the first row stays blank.
    fireEvent.blur(second);
    expect(latest).toEqual([
      { code: 0, value: "" },
      { code: 2, name: "time-offset", value: "" },
    ]);
    expect(searchBoxes()[0].value).toBe("");
  });

  it("a code typed into the second blank row and committed by Tab lands in that row", async () => {
    open([
      { code: 0, value: "" },
      { code: 0, value: "" },
    ]);
    const second = searchBoxes()[1];
    fireEvent.focus(second);
    fireEvent.change(second, { target: { value: "43" } });
    // The catalogue has loaded: the list offers the code just typed.
    await screen.findByText("vendor-encapsulated-options");
    fireEvent.blur(second);
    expect(latest).toEqual([
      { code: 0, value: "" },
      { code: 43, name: "vendor-encapsulated-options", value: "" },
    ]);
    expect(searchBoxes()[0].value).toBe("");
  });

  it("a value typed into the second blank row lands in that row", async () => {
    open([
      { code: 0, value: "" },
      { code: 0, value: "" },
    ]);
    fireEvent.change(valueBoxes()[1], { target: { value: "x" } });
    expect(latest).toEqual([
      { code: 0, value: "" },
      { code: 0, value: "x" },
    ]);
    expect(valueBoxes().map((b) => b.value)).toEqual(["", "x"]);
  });

  it("with a standard option between the rows, a pick in the second row sets that row only", async () => {
    open([
      { code: 0, value: "" },
      { code: 3, name: "routers", value: ["10.0.0.1"] },
      { code: 0, value: "" },
    ]);
    expect(searchBoxes()).toHaveLength(2);
    await pickTimeOffset(searchBoxes()[1]);
    expect(latest).toEqual([
      { code: 0, value: "" },
      { code: 3, name: "routers", value: ["10.0.0.1"] },
      { code: 2, name: "time-offset", value: "" },
    ]);
  });

  it("removing the first of two blank rows keeps the second row", async () => {
    const first: DHCPOption = { code: 0, value: "" };
    const second: DHCPOption = { code: 0, value: "" };
    open([first, second]);
    const remove = screen.getAllByRole("button", { name: "Remove option" });
    fireEvent.mouseDown(remove[0]);
    fireEvent.click(remove[0]);
    expect(latest).toHaveLength(1);
    expect(latest[0]).toBe(second);
  });
});

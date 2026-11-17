/**
 * @vitest-environment jsdom
 *
 * What the DHCP options editor shows is what it saves (#3543). A custom row
 * given the code of a standard option (6, DNS Servers) left the custom list
 * and joined that option's field, which kept showing the text it was drawn
 * with. With the field filled, the form held two rows of option 6, and a
 * client class save sent the hidden row's empty value. A standard code is
 * now refused in a custom row, with a hint naming its field.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { DHCPOption } from "@/lib/api";
import { optionsToMap } from "./dhcpOptionKeys";

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listOptionCodes: () =>
      Promise.resolve([
        {
          code: 6,
          name: "domain-name-servers",
          kind: "ip-list",
          description: "DNS resolver IP list",
        },
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

function dnsField() {
  return screen.getByLabelText("DNS Servers (option 6)") as HTMLInputElement;
}

async function typeCode(box: HTMLInputElement, code: string) {
  fireEvent.focus(box);
  fireEvent.change(box, { target: { value: code } });
  // The catalogue has loaded: the list offers option 6.
  await screen.findByText("domain-name-servers");
}

const filled: DHCPOption[] = [
  { code: 6, name: "dns-servers", value: ["192.0.2.53"] },
  { code: 0, value: "" },
];

afterEach(cleanup);

describe("a standard option's code in a custom row", () => {
  it("is refused when typed beside the filled field, so a save sends what the field shows", async () => {
    open(filled);
    expect(dnsField().value).toBe("192.0.2.53");
    await typeCode(searchBoxes()[0], "6");
    fireEvent.blur(searchBoxes()[0]);

    expect(latest).toEqual(filled);
    expect(searchBoxes()).toHaveLength(1);
    expect(searchBoxes()[0].value).toBe("");
    expect(dnsField().value).toBe("192.0.2.53");
    expect(optionsToMap(latest)).toEqual({ "dns-servers": ["192.0.2.53"] });
    expect(screen.getByRole("alert").textContent).toContain(
      "DNS Servers (option 6)",
    );

    // A code of its own is taken, and the hint goes.
    fireEvent.focus(searchBoxes()[0]);
    fireEvent.change(searchBoxes()[0], { target: { value: "43" } });
    fireEvent.blur(searchBoxes()[0]);
    expect(latest.map((o) => o.code)).toEqual([6, 43]);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("is refused when picked from the list", async () => {
    open(filled);
    await typeCode(searchBoxes()[0], "6");
    const suggestion = screen.getByText("domain-name-servers");
    fireEvent.mouseDown(suggestion);
    fireEvent.click(suggestion);

    expect(latest).toEqual(filled);
    expect(searchBoxes()).toHaveLength(1);
    expect(screen.queryByText("vendor-class-identifier")).toBeNull();
    expect(screen.getByRole("alert").textContent).toContain(
      "DNS Servers (option 6)",
    );
    fireEvent.blur(searchBoxes()[0]);
    expect(latest).toEqual(filled);
  });

  it("with the field empty, keeps a typed value in its custom row instead of hiding it", async () => {
    open([{ code: 0, value: "" }]);
    fireEvent.change(screen.getByPlaceholderText("value"), {
      target: { value: "192.0.2.9" },
    });
    await typeCode(searchBoxes()[0], "6");
    fireEvent.blur(searchBoxes()[0]);

    expect(latest).toEqual([{ code: 0, value: "192.0.2.9" }]);
    expect(searchBoxes()).toHaveLength(1);
    expect(
      (screen.getByPlaceholderText("value") as HTMLInputElement).value,
    ).toBe("192.0.2.9");
    expect(dnsField().value).toBe("");
  });

  it("leaves its hint with the row it was given for when a row above it is removed", async () => {
    const next = { code: 43, name: "vendor-encapsulated-options", value: "x" };
    open([{ code: 0, value: "" }, next]);
    await typeCode(searchBoxes()[0], "6");
    fireEvent.blur(searchBoxes()[0]);
    expect(screen.getByRole("alert").textContent).toContain(
      "DNS Servers (option 6)",
    );

    // Rows are keyed by index: the first row's instance now shows the next.
    const remove = screen.getAllByRole("button", { name: "Remove option" });
    fireEvent.mouseDown(remove[0]);
    fireEvent.click(remove[0]);

    expect(latest).toEqual([next]);
    expect(searchBoxes()).toHaveLength(1);
    expect(searchBoxes()[0].value).toMatch(
      /^43 \S vendor-encapsulated-options$/,
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

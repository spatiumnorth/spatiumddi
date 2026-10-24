/**
 * @vitest-environment jsdom
 *
 * #2482 — focusing and leaving the DNS Servers field must not drop a stored
 * fourth address.
 */
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { DHCPOption } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  dhcpApi: { listOptionCodes: () => Promise.resolve([]) },
}));
import { DHCPOptionsEditor } from "./DHCPOptionsEditor";

let latest: DHCPOption[] = [];
const IPS = ["10.0.0.53", "10.0.0.54", "10.0.0.55", "10.0.0.56"];

function Harness() {
  const [v, setV] = useState<DHCPOption[]>([
    { code: 6, name: "dns-servers", value: IPS },
  ]);
  latest = v;
  return <DHCPOptionsEditor value={v} onChange={setV} />;
}

describe("DNS Servers keeps every stored address (#2482)", () => {
  it("a click and Tab through the field leaves all four stored", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Harness />
      </QueryClientProvider>,
    );
    const box = screen.getByText("DNS Servers (option 6)", {
      selector: "label",
    }).nextElementSibling as HTMLInputElement;
    expect(box.value).toBe(IPS.join(", "));
    fireEvent.focus(box);
    fireEvent.blur(box);
    expect(latest.find((o) => o.code === 6)?.value).toEqual(IPS);
  });
});

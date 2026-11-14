/**
 * The Subnet Planner's + Subnet / + Block pre-fill never answers a CIDR a
 * sibling holds (#3711). Under an IPv6 node it was always the node's first
 * /(p+16); under an IPv4 node of /23 or longer, the node's own network.
 */
import { describe, expect, it } from "vitest";
import { cidrContains } from "@/lib/cidr";
import { suggestChildCidr } from "@/lib/plan-suggest";

type N = Parameters<typeof suggestChildCidr>[0];
const node = (network: string, children: N[] = []): N =>
  ({
    id: network,
    network,
    name: "",
    description: "",
    kind: "block",
    children,
  }) as never;

/** Press + Subnet `n` times under `parent`; return each pre-fill. */
function press(parent: string, n: number): string[] {
  const kids: N[] = [];
  for (let i = 0; i < n; i++)
    kids.push(node(suggestChildCidr(node(parent), kids)));
  return kids.map((k) => k.network);
}

describe("planner pre-fill (#3711)", () => {
  it.each([
    "fd71:a7:0:200::/56",
    "10.109.96.0/24",
    "10.109.112.0/20",
    "10.0.0.0/29",
  ])("%s: two presses give disjoint children inside it", (parent) => {
    const [x, y] = press(parent, 2);
    expect(x).not.toBe(y);
    expect(cidrContains(parent, x)).toBe(true);
    expect(cidrContains(parent, y)).toBe(true);
  });

  it("keeps the first-free-slot answer under a /20", () => {
    expect(press("10.109.112.0/20", 2)).toEqual([
      "10.109.112.0/28",
      "10.109.112.16/28",
    ]);
    expect(press("fd71:a7:0:200::/56", 2)).toEqual([
      "fd71:a7:0:200::/72",
      "fd71:a7:0:200:100::/72",
    ]);
  });

  it("many presses under an IPv6 node never repeat or overlap", () => {
    const all = press("fd71:a7:0:200::/56", 40);
    expect(new Set(all).size).toBe(40);
    all.forEach((c) =>
      expect(cidrContains("fd71:a7:0:200::/56", c)).toBe(true),
    );
  });

  it("answers empty, never a sibling, when nothing fits", () => {
    const full = node("10.0.0.0/30", [node("10.0.0.0/30")]);
    expect(suggestChildCidr(node("10.0.0.0/30"), full.children)).toBe("");
  });

  it.each(["10.0.0.0/32", "10.0.0.0/31", "fd00::/128", "fd00::/127"])(
    "%s: no room for a child, so empty",
    (parent) => {
      expect(suggestChildCidr(node(parent), [])).toBe("");
    },
  );

  it("fills past siblings at both edges of the node", () => {
    const p = "fd00::/120";
    const kids = [node("fd00::/121"), node("fd00::80/122")];
    const next = suggestChildCidr(node(p), kids);
    expect(cidrContains(p, next)).toBe(true);
    expect(next).toBe("fd00::c0/127");
    const v4 = suggestChildCidr(node("10.0.0.0/24"), [
      node("10.0.0.0/25"),
      node("10.0.0.128/26"),
    ]);
    expect(v4).toBe("10.0.0.192/30");
  });

  it("ignores siblings of the other family", () => {
    expect(suggestChildCidr(node("10.0.0.0/24"), [node("::/0")])).toBe(
      suggestChildCidr(node("10.0.0.0/24"), []),
    );
  });
});

describe("+ Subnet under an IPv6 node starts on /64 (#3850)", () => {
  it.each(["fd5e:1110:d::/56", "fd5e:1110:e::/60", "fd5e:1110:f::/48"])(
    "%s",
    (p) => {
      const c = suggestChildCidr(node(p), [], "subnet");
      expect(c.endsWith("/64")).toBe(true);
      expect(cidrContains(p, c)).toBe(true);
    },
  );
  it("skips a /64 a sibling holds", () => {
    const c = suggestChildCidr(
      node("fd5e:1110:d::/56"),
      [node("fd5e:1110:d::/64")],
      "subnet",
    );
    expect(c).toBe("fd5e:1110:d:1::/64");
  });
  it("+ Block keeps its size", () => {
    expect(suggestChildCidr(node("fd5e:1110:d::/56"), [], "block")).toBe(
      "fd5e:1110:d::/72",
    );
  });
});

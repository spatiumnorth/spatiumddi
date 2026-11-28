import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// #4847: counts of one that sat where the #4780 guard cannot look (a word
// between the count and the plural, or a plural off its list).
const SITES: [string, RegExp][] = [
  ["pages/ipam/IPAMPage.tsx", /\} IP addresses`/],
  ["pages/ipam/IPAMPage.tsx", /\bdistinct\s+tag keys/],
  ["pages/ipam/BulkAllocateModal.tsx", /\} IPs total/],
  ["pages/ipam/BulkAllocateModal.tsx", /\} IPs`/],
  ["pages/ipam/ResizeModals.tsx", /\} pools, /],
  ["pages/admin/DomainsPage.tsx", /\$\{days\} days/],
  ["pages/dhcp/DHCPPage.tsx", /\} (pools|reservations) (changed|removed)`/],
  ["pages/dhcp/DHCPPage.tsx", /\} leases on wire/],
];

describe("count of one in the singular (#4847)", () => {
  it.each(SITES)("%s has no fixed plural %s", (file, re) => {
    const text = readFileSync(resolve(__dirname, "..", file), "utf8");
    expect(text).not.toMatch(re);
  });
});

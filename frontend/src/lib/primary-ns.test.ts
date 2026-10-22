import { describe, expect, it } from "vitest";
import { primaryNsError } from "./primary-ns";

// The same lists are in backend/tests/test_zone_primary_ns_host_name_2075.py
// and agent/dns/tests/test_zone_apex_render.py: change all three together, or
// the dialog accepts what the API refuses (or the reverse).
const BAD = [
  "ns_1.example.test.",
  "a".repeat(64) + ".example.test.",
  "ns1",
  "ns1.",
  "ns1..example.test.",
  ".example.test.",
  "-ns1.example.test.",
  "ns1-.example.test.",
  "ns1.example.test..",
  "bücher.example.test.",
  ("a".repeat(63) + ".").repeat(4) + "test.",
];
const GOOD = [
  "ns1.example.test.",
  "ns1.example.test",
  "NS1.Other-Corp.net.",
  "a".repeat(63) + ".test.",
  "ns1.xn--bcher-kva.example.",
  "1ns.example.test.",
];

describe("primaryNsError", () => {
  it.each([...GOOD, ""])("accepts %s", (v) =>
    expect(primaryNsError(v)).toBeNull(),
  );
  it.each(BAD)("refuses %s", (v) => expect(primaryNsError(v)).not.toBeNull());
});

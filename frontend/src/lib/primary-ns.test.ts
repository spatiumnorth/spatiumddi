import { describe, expect, it } from "vitest";
import { primaryNsError } from "./primary-ns";

describe("primaryNsError", () => {
  it.each([
    "",
    "ns1.example.com.",
    "ns1.example.com",
    "a".repeat(63) + ".test.",
  ])("accepts %s", (v) => expect(primaryNsError(v)).toBeNull());

  it.each([
    "ns_1.example.com.",
    "a".repeat(64) + ".example.com.",
    "ns1",
    "ns1.",
    "ns1..example.com.",
    "-ns1.example.com.",
  ])("refuses %s", (v) => expect(primaryNsError(v)).not.toBeNull());
});

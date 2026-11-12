import { describe, expect, it } from "vitest";
import { servedApexWords } from "./servedApexWords";

const base = {
  ns: ["ns1.z.test."],
  source: "placeholder" as const,
  placeholder_glue_loopback: false,
  placeholder_reason: null,
  unaddressed_primary_ns: null,
  unaddressed_ns: [],
};
const all = (r: ReturnType<typeof servedApexWords>) =>
  [r.warning, r.unaddressed].filter(Boolean).join(" | ");

describe("served apex words (#3840)", () => {
  it("names the Primary NS when the placeholder has an address", () => {
    const w = all(
      servedApexWords(
        {
          ...base,
          placeholder_reason: "primary_ns_has_no_address",
          unaddressed_primary_ns: "ns.z.test.",
        },
        "z.test",
      ),
    );
    expect(w).toContain("ns.z.test.");
    expect(w).not.toContain("names none of its own");
    expect(w).not.toContain("Set a Primary NS");
  });

  it("does not call an outside name server glued", () => {
    const w = all(
      servedApexWords(
        {
          ...base,
          source: "declared",
          ns: ["ns.example.org.", "ns1.z.test."],
          placeholder_glue_loopback: true,
        },
        "z.test",
      ),
    );
    expect(w).toContain("ns1.z.test.");
    expect(w).not.toContain("ns.example.org.");
  });

  it("does not call a zone BIND will not load served", () => {
    const w = all(
      servedApexWords(
        {
          ...base,
          source: "declared",
          ns: ["ns1.z.test.", "ns2.z.test."],
          placeholder_glue_loopback: true,
          unaddressed_ns: ["ns2.z.test."],
        },
        "z.test",
      ),
    );
    expect(w).toContain("ns1.z.test., ns2.z.test.");
    expect(w).toContain("will not load");
    expect(w).not.toContain("served glued");
  });
});

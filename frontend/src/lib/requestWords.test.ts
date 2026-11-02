import { describe, expect, it } from "vitest";
import { fieldWords, plainText, submitErrorWords } from "./requestWords";

describe("plainText", () => {
  it("drops bold and code marks", () => {
    expect(plainText("Create **A** `x` and `y`")).toBe("Create A x and y");
  });
  it("keeps a wildcard owner's asterisk", () => {
    expect(
      plainText("Create **A** record `*.lab` in zone `example.test.`"),
    ).toBe("Create A record *.lab in zone example.test.");
    expect(plainText("Create **TXT** record `*`")).toBe("Create TXT record *");
  });
});

describe("fieldWords", () => {
  it("never asks a person for a UUID, even for an unknown field", () => {
    const w = fieldWords("x", "group_id", "Group Id", "UUID of the group");
    expect(w.label).toBe("Group");
    expect(w.hint).toBeUndefined();
  });
});

describe("submitErrorWords", () => {
  const labels: Record<string, string> = {
    ttl: "TTL (seconds)",
    status: "Status",
    subnet_id: "Subnet",
    prefix_len: "Prefix length",
  };
  const label = (f: string) => labels[f] ?? f;
  const fail = (detail: unknown) => ({ response: { data: { detail } } });
  const at = (field: string) => ["body", "args", field];

  it("words each error by its type, in the form's labels", () => {
    expect(
      submitErrorWords(
        fail([
          { type: "missing", loc: at("subnet_id"), msg: "Field required" },
          {
            type: "greater_than_equal",
            loc: at("ttl"),
            msg: "Input should be greater than or equal to 60",
            ctx: { ge: 60 },
          },
          {
            type: "int_parsing",
            loc: at("prefix_len"),
            msg: "Input should be a valid integer, unable to parse string as an integer",
          },
          {
            type: "value_error",
            loc: at("status"),
            msg: "Value error, status must be one of: allocated, reserved",
          },
        ]),
        label,
      ),
    ).toBe(
      "Subnet is required; TTL (seconds) must be at least 60; Prefix length must be a whole number; Status must be one of: allocated, reserved.",
    );
  });

  it("does not depend on Pydantic's wording for typed errors", () => {
    expect(
      submitErrorWords(
        fail([
          {
            type: "less_than_equal",
            loc: at("ttl"),
            msg: "anything",
            ctx: { le: 604800 },
          },
        ]),
        label,
      ),
    ).toBe("TTL (seconds) must be at most 604800.");
  });

  it("leaves a message with its own semicolons whole", () => {
    expect(
      submitErrorWords(
        fail([
          {
            type: "value_error",
            loc: at("value"),
            msg: "Value error, A record value contains a ';'; remove it",
          },
        ]),
        (f) => (f === "value" ? "Value" : f),
      ),
    ).toBe("Value: a record value contains a ';'; remove it.");
  });

  it("returns null for anything that is not a field-error list", () => {
    expect(submitErrorWords(fail("Unknown request kind 'x'"), label)).toBe(
      null,
    );
    expect(submitErrorWords(new Error("Network Error"), label)).toBe(null);
    expect(
      submitErrorWords(
        fail([{ type: "missing", loc: ["body", "kind"] }]),
        label,
      ),
    ).toBe(null);
  });
});

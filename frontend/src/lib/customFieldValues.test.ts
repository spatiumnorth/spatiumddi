import { describe, expect, it } from "vitest";
import type { CustomField } from "@/lib/api";
import {
  customFieldChecked,
  customFieldDefault,
  withCustomFieldDefaults,
} from "./customFieldValues";

function def(
  over: Partial<CustomField> & Pick<CustomField, "name">,
): CustomField {
  return {
    id: `cf-${over.name}`,
    resource_type: "ip_address",
    label: over.name,
    field_type: "text",
    options: null,
    is_required: false,
    is_searchable: false,
    default_value: null,
    display_order: 0,
    description: "",
    ...over,
  };
}

describe("customFieldChecked (#1303)", () => {
  it.each([true, "true", "TRUE", " yes ", "1", "on"])(
    "%j reads as checked",
    (v) => expect(customFieldChecked(v)).toBe(true),
  );
  it.each([false, "false", "False", "0", "no", "off", "", null, undefined])(
    "%j reads as unchecked",
    (v) => expect(customFieldChecked(v)).toBe(false),
  );
});

describe("customFieldDefault (#1303)", () => {
  it("is the Default Value for a text field, and nothing without one", () => {
    expect(
      customFieldDefault(def({ name: "a", default_value: "netops" })),
    ).toBe("netops");
    expect(customFieldDefault(def({ name: "a" }))).toBeUndefined();
    expect(
      customFieldDefault(def({ name: "a", default_value: "  " })),
    ).toBeUndefined();
  });

  it("reads a boolean default as true or false, and skips anything else", () => {
    const bool = (default_value: string) =>
      customFieldDefault(
        def({ name: "b", field_type: "boolean", default_value }),
      );
    expect(bool("false")).toBe(false);
    expect(bool("True")).toBe(true);
    expect(bool("maybe")).toBeUndefined();
  });

  it("skips a select default its options do not offer", () => {
    const select = (default_value: string) =>
      customFieldDefault(
        def({
          name: "s",
          field_type: "select",
          options: ["gold", "silver"],
          default_value,
        }),
      );
    expect(select("silver")).toBe("silver");
    expect(select("bronze")).toBeUndefined();
  });

  it("skips a number default that is not a number", () => {
    const number = (default_value: string) =>
      customFieldDefault(
        def({ name: "n", field_type: "number", default_value }),
      );
    expect(number("42")).toBe("42");
    expect(number("forty-two")).toBeUndefined();
  });
});

describe("withCustomFieldDefaults (#1303)", () => {
  const defs = [
    def({ name: "owner", default_value: "netops" }),
    def({ name: "managed", field_type: "boolean", default_value: "true" }),
    def({ name: "notes" }),
  ];

  it("fills the fields the form does not hold", () => {
    expect(withCustomFieldDefaults(defs, {})).toEqual({
      owner: "netops",
      managed: true,
    });
  });

  it("keeps what the form holds, an emptied or unchecked field included", () => {
    expect(
      withCustomFieldDefaults(defs, { owner: "", managed: false }),
    ).toEqual({
      owner: "",
      managed: false,
    });
  });

  it("returns the same object when there is nothing to fill", () => {
    const values = { owner: "helpdesk", managed: false };
    expect(withCustomFieldDefaults(defs, values)).toBe(values);
  });
});

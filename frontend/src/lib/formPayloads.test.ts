import { describe, expect, it } from "vitest";
import {
  blocklistPayload,
  customFieldCreatePayload,
  customFieldUpdatePayload,
  poolHealthCheckFields,
  serverApiPortField,
  staticDuidField,
  type CustomFieldForm,
} from "./formPayloads";

// #1596: an update endpoint reads an explicit `null` as "clear". A field the
// form hides for the current mode must therefore be ABSENT from an edit body
// (the stored value survives), while a visible field the operator empties
// still goes out as null.

describe("blocklistPayload", () => {
  // A Manual list in NXDOMAIN mode that still holds a feed URL and a
  // sinkhole IP from an earlier mode — both inputs are hidden.
  const manualNx = {
    name: "corp-block",
    description: "edited description",
    category: "custom",
    sourceType: "manual",
    feedUrl: "https://example.com/feed.txt",
    feedFormat: "hosts",
    blockMode: "nxdomain",
    sinkholeIp: "10.0.0.1",
    updateHours: 24,
    feedWildcard: true,
    enabled: true,
  };

  it("omits the hidden feed_url and sinkhole_ip on edit", () => {
    const body = blocklistPayload(manualNx, true);
    expect(body).not.toHaveProperty("feed_url");
    expect(body).not.toHaveProperty("sinkhole_ip");
    expect(body.description).toBe("edited description");
  });

  it("sends null for the hidden fields on create", () => {
    const body = blocklistPayload(manualNx, false);
    expect(body.feed_url).toBeNull();
    expect(body.sinkhole_ip).toBeNull();
  });

  it("sends null when a visible field is deliberately emptied", () => {
    const body = blocklistPayload(
      {
        ...manualNx,
        sourceType: "url",
        feedUrl: "",
        blockMode: "sinkhole",
        sinkholeIp: "",
      },
      true,
    );
    expect(body).toHaveProperty("feed_url", null);
    expect(body).toHaveProperty("sinkhole_ip", null);
  });

  it("sends the visible values", () => {
    const body = blocklistPayload(
      { ...manualNx, sourceType: "url", blockMode: "sinkhole" },
      true,
    );
    expect(body.feed_url).toBe("https://example.com/feed.txt");
    expect(body.sinkhole_ip).toBe("10.0.0.1");
  });
});

describe("poolHealthCheckFields", () => {
  it.each(["none", "icmp"] as const)(
    "omits the hidden target port on edit (hc_type=%s)",
    (hcType) => {
      const out = poolHealthCheckFields(
        { hcType, hcPort: 8443, hcVerifyTls: true },
        true,
      );
      expect(out).not.toHaveProperty("hc_target_port");
      expect(out).not.toHaveProperty("hc_verify_tls");
    },
  );

  it("sends null for the hidden port on create", () => {
    const out = poolHealthCheckFields(
      { hcType: "icmp", hcPort: 80, hcVerifyTls: false },
      false,
    );
    expect(out).toEqual({ hc_target_port: null, hc_verify_tls: false });
  });

  it("sends the visible port and TLS flag for https", () => {
    const out = poolHealthCheckFields(
      { hcType: "https", hcPort: 443, hcVerifyTls: true },
      true,
    );
    expect(out).toEqual({ hc_target_port: 443, hc_verify_tls: true });
  });

  it("sends null when the visible port is emptied", () => {
    const out = poolHealthCheckFields(
      { hcType: "tcp", hcPort: 0, hcVerifyTls: false },
      true,
    );
    expect(out).toHaveProperty("hc_target_port", null);
  });
});

describe("staticDuidField", () => {
  it("omits the hidden DUID on an IPv4 edit", () => {
    expect(staticDuidField({ isV6: false, duid: "00:03:00:01" }, true)).toEqual(
      {},
    );
  });

  it("sends null for the hidden DUID on an IPv4 create", () => {
    expect(staticDuidField({ isV6: false, duid: "" }, false)).toEqual({
      duid: null,
    });
  });

  it("sends the visible DUID on v6, null when emptied", () => {
    expect(staticDuidField({ isV6: true, duid: "00:03" }, true)).toEqual({
      duid: "00:03",
    });
    expect(staticDuidField({ isV6: true, duid: "" }, true)).toEqual({
      duid: null,
    });
  });
});

describe("serverApiPortField", () => {
  it("omits the hidden api_port for a cloud driver on edit", () => {
    expect(
      serverApiPortField(
        { driver: "route53", cloud: true, apiPort: "953" },
        true,
      ),
    ).toEqual({});
  });

  it("omits the hidden api_port for technitium_api on edit", () => {
    expect(
      serverApiPortField(
        { driver: "technitium_api", cloud: false, apiPort: "" },
        true,
      ),
    ).toEqual({});
  });

  it("sends null for a cloud driver on create", () => {
    expect(
      serverApiPortField(
        { driver: "route53", cloud: true, apiPort: "" },
        false,
      ),
    ).toEqual({ api_port: null });
  });

  it("sends the visible port, null when emptied", () => {
    expect(
      serverApiPortField(
        { driver: "bind9", cloud: false, apiPort: "953" },
        true,
      ),
    ).toEqual({ api_port: 953 });
    expect(
      serverApiPortField({ driver: "bind9", cloud: false, apiPort: "" }, true),
    ).toEqual({ api_port: null });
  });
});

describe("customField payloads", () => {
  const textField: CustomFieldForm = {
    resource_type: "subnet",
    name: "owner",
    label: "Owner",
    field_type: "text",
    options: "a, b",
    is_required: false,
    is_searchable: true,
    default_value: "",
    display_order: 0,
    description: "",
  };

  it("omits the hidden options on edit of a non-select field", () => {
    const body = customFieldUpdatePayload(textField);
    expect(body).not.toHaveProperty("options");
    expect(body).not.toHaveProperty("resource_type");
    expect(body).not.toHaveProperty("name");
    expect(body).not.toHaveProperty("field_type");
  });

  it("sends the options on edit of a select field", () => {
    const body = customFieldUpdatePayload({
      ...textField,
      field_type: "select",
    });
    expect(body.options).toEqual(["a", "b"]);
  });

  it("sends null options on create of a non-select field", () => {
    expect(customFieldCreatePayload(textField).options).toBeNull();
  });
});

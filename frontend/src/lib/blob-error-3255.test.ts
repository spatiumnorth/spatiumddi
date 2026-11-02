import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AxiosError,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from "axios";

import {
  api,
  conformityApi,
  dnsApi,
  e911Api,
  formatApiError,
  ipamIoApi,
  rethrowBlobError,
  supportBundleApi,
} from "@/lib/api";
import { exportErrorMessage } from "@/lib/refusal";

function blobError(body: BlobPart | Blob, status = 403) {
  return {
    message: `Request failed with status code ${status}`,
    response: {
      status,
      data: (body instanceof Blob ? body : new Blob([body])) as unknown,
    },
  };
}

describe("rethrowBlobError (#3255)", () => {
  it("decodes a Blob error body so the server's reason is readable", async () => {
    const err = blobError(JSON.stringify({ detail: "Permission denied: x" }));
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    expect(err.response.status).toBe(403);
    expect(formatApiError(err)).toBe("Permission denied: x");
    expect(exportErrorMessage(err, "the report")).toMatch(
      /not permitted to export the report \(Permission denied: x\)/,
    );
  });

  it("keeps the error's own type, so instanceof checks still hold", async () => {
    const err = new AxiosError("Request failed with status code 403");
    err.response = {
      status: 403,
      statusText: "Forbidden",
      headers: {},
      config: {} as InternalAxiosRequestConfig,
      data: new Blob([JSON.stringify({ detail: "nope" })]),
    };
    const thrown = await rethrowBlobError(err).catch((e: unknown) => e);
    expect(thrown).toBe(err);
    expect(thrown).toBeInstanceOf(AxiosError);
    expect(formatApiError(thrown)).toBe("nope");
  });

  it("keeps a 422's detail array for formatApiError to flatten", async () => {
    const err = blobError(
      JSON.stringify({ detail: [{ loc: ["query", "f"], msg: "bad f" }] }),
      422,
    );
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    expect(formatApiError(err)).toBe("query.f: bad f");
  });

  it("uses a short plain-text body as the reason", async () => {
    const err = blobError("Service paused for maintenance", 503);
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    expect(exportErrorMessage(err, "the report")).toBe(
      "Exporting the report is unavailable right now (Service paused for maintenance).",
    );
  });

  it.each([
    ["an empty body", ""],
    ["a proxy's HTML page", "<html><body>502 Bad Gateway</body></html>"],
    ["JSON without a detail", JSON.stringify({ ok: false })],
  ])("never shows a status code or raw bytes for %s", async (_, body) => {
    const err = blobError(body, 403);
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    const text = exportErrorMessage(err, "the report");
    expect(text).toBe("You're not permitted to export the report.");
    expect(text).not.toMatch(/status code|<html/);
  });

  it("does not throw from the decoder when the body cannot be read", async () => {
    const unreadable = new Blob(["x"]);
    unreadable.text = () => Promise.reject(new Error("read failed"));
    const err = blobError(unreadable, 403);
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    expect(exportErrorMessage(err, "the report")).toBe(
      "You're not permitted to export the report.",
    );
  });

  it("re-throws a non-Blob error untouched", async () => {
    const err = { response: { status: 500, data: { detail: "boom" } } };
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    expect(err.response.data).toEqual({ detail: "boom" });
    await expect(rethrowBlobError(undefined)).rejects.toBeUndefined();
  });
});

// Every file download in the client is requested as a Blob; each must hand
// its caller a refusal it can read, not "Request failed with status code 403".
describe("blob downloads decode a refusal (#3255)", () => {
  const original = api.defaults.adapter;
  beforeEach(() => {
    const refuse: AxiosAdapter = (config) =>
      Promise.reject(
        new AxiosError(
          "Request failed with status code 403",
          AxiosError.ERR_BAD_REQUEST,
          config,
          {},
          {
            status: 403,
            statusText: "Forbidden",
            headers: {},
            config,
            data: new Blob([
              JSON.stringify({ detail: "Permission denied: need it" }),
            ]),
          },
        ),
      );
    api.defaults.adapter = refuse;
  });
  afterEach(() => {
    api.defaults.adapter = original;
  });

  it.each([
    ["conformity PDF", () => conformityApi.exportPdf()],
    ["E911 CSV", () => e911Api.download("csv")],
    ["E911 IOS snippets", () => e911Api.download("ios")],
    ["IPAM export", () => ipamIoApi.download({ format: "csv" })],
    ["DNS zone records", () => dnsApi.exportZoneRecords("g", "z", "csv")],
    ["DNS import template", () => dnsApi.zoneImportTemplate("g", "z")],
    ["DNS export all zones", () => dnsApi.exportAllZones("g")],
    ["support bundle", () => supportBundleApi.download(true)],
  ])("%s", async (_, call: () => Promise<unknown>) => {
    const err = await call().then(
      () => {
        throw new Error("expected a rejection");
      },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AxiosError);
    expect((err as AxiosError).response?.status).toBe(403);
    expect(formatApiError(err)).toBe("Permission denied: need it");
  });
});

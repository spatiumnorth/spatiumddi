import { afterEach, describe, expect, it } from "vitest";
import { AxiosError, type AxiosAdapter } from "axios";

import { api, dnsApi } from "@/lib/api";

const original = api.defaults.adapter;
afterEach(() => {
  api.defaults.adapter = original;
});

function serve(listStatus: number) {
  const urls: string[] = [];
  const adapter: AxiosAdapter = async (config) => {
    urls.push(config.url ?? "");
    const ok = (data: unknown, status = 200) => ({
      data,
      status,
      statusText: "",
      headers: {},
      config,
    });
    if (config.url === "/dns/groups/g1/zones") {
      if (listStatus === 200) return ok([{ id: "all" }]);
      throw new AxiosError("x", "ERR", config, null, {
        ...ok({}, listStatus),
      } as never);
    }
    return ok([{ id: "z1" }]);
  };
  api.defaults.adapter = adapter;
  return urls;
}

describe("dnsApi.listZones (#4854)", () => {
  it("asks for the writable zones when the group's zone list is refused", async () => {
    const urls = serve(403);
    const zones = await dnsApi.listZones("g1", undefined, "s1");
    expect(zones.map((z) => z.id)).toEqual(["z1"]);
    expect(urls).toContain("/ipam/subnets/s1/writable-zones");
  });

  it("keeps the group's zone list when it is readable", async () => {
    const urls = serve(200);
    const zones = await dnsApi.listZones("g1", undefined, "s1");
    expect(zones.map((z) => z.id)).toEqual(["all"]);
    expect(urls).toEqual(["/dns/groups/g1/zones"]);
  });

  it("does not mask other failures", async () => {
    serve(500);
    await expect(dnsApi.listZones("g1", undefined, "s1")).rejects.toBeTruthy();
  });
});

import { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { afterEach, describe, expect, it } from "vitest";

import { api } from "./api";
import { getAccessToken, setAccessToken } from "./authToken";

function unauthorized(config: InternalAxiosRequestConfig): AxiosError {
  return new AxiosError("401", "ERR_BAD_REQUEST", config, null, {
    status: 401,
    statusText: "Unauthorized",
    data: {},
    headers: {},
    config,
  });
}

afterEach(() => {
  setAccessToken(null);
  api.defaults.adapter = undefined;
});

describe("401 interceptor (#2960)", () => {
  it("retries with the token another tab already moved this tab to, without refreshing", async () => {
    setAccessToken("T1");
    const urls: string[] = [];
    api.defaults.adapter = async (config) => {
      urls.push(`${config.url} ${String(config.headers.Authorization)}`);
      if (config.url === "/auth/refresh") throw new Error("must not refresh");
      if (config.headers.Authorization === "Bearer T1") {
        // A broadcast from another tab lands while this request is in flight.
        setAccessToken("T2");
        throw unauthorized(config);
      }
      return {
        data: { ok: true },
        status: 200,
        statusText: "OK",
        headers: {},
        config,
      };
    };
    const res = await api.get("/x");
    expect(res.data).toEqual({ ok: true });
    expect(urls).toEqual(["/x Bearer T1", "/x Bearer T2"]);
    expect(getAccessToken()).toBe("T2");
  });
});

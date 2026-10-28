import { describe, expect, it } from "vitest";

import { bucketLoss, summariseLoss } from "./dhcp-loss";

describe("bucketLoss", () => {
  it("passes a measured value through, including zero", () => {
    expect(bucketLoss({ socket_drop: 12 })).toBe(12);
    expect(bucketLoss({ socket_drop: 0 })).toBe(0);
  });

  it("reports an explicit null as not measured", () => {
    expect(bucketLoss({ socket_drop: null })).toBeNull();
  });

  it("reports an OMITTED key as not measured, not as zero", () => {
    // A control plane older than #980 does not send the field at all. The
    // generated type says `number | null`, so `tsc` cannot catch this —
    // only the runtime coalesce does. Reading it as 0 would tell the
    // operator "nothing was lost" about a server nobody measured, which is
    // the exact false reassurance the issue was filed about.
    expect(bucketLoss({})).toBeNull();
    expect(bucketLoss({ socket_drop: undefined })).toBeNull();
  });
});

describe("summariseLoss", () => {
  it("an empty window is not measured", () => {
    expect(summariseLoss([])).toEqual({
      measured: false,
      total: 0,
      evicted: 0,
      evictionMeasured: false,
    });
  });

  it("all-unmeasured is not measured", () => {
    expect(summariseLoss([{}, { socket_drop: null }])).toMatchObject({
      measured: false,
      total: 0,
    });
  });

  it("measured zero is measured — a clean bill, not an absent one", () => {
    expect(
      summariseLoss([{ socket_drop: 0 }, { socket_drop: 0 }]),
    ).toMatchObject({
      measured: true,
      total: 0,
    });
  });

  it("sums measured buckets", () => {
    expect(
      summariseLoss([{ socket_drop: 3 }, { socket_drop: 4 }]),
    ).toMatchObject({
      measured: true,
      total: 7,
    });
  });

  it("a partly-measured window reports what it knows", () => {
    // One agent restart mid-window must not hide the loss either side of it.
    expect(
      summariseLoss([{ socket_drop: 5 }, {}, { socket_drop: 2 }]),
    ).toMatchObject({ measured: true, total: 7 });
  });
});

describe("#2889 queue_evicted", () => {
  it("adds queue evictions to kernel drops", () => {
    expect(bucketLoss({ socket_drop: 3, queue_evicted: 40 })).toBe(43);
  });

  it("an unmeasured eviction adds nothing and voids nothing", () => {
    // A server without a raw socket still measures its kernel drops.
    expect(bucketLoss({ socket_drop: 3, queue_evicted: null })).toBe(3);
    expect(bucketLoss({ socket_drop: 3 })).toBe(3);
  });

  it("evictions alone are a measurement", () => {
    expect(bucketLoss({ socket_drop: null, queue_evicted: 0 })).toBe(0);
  });

  it("summarises the evicted share and whether it was measured", () => {
    expect(
      summariseLoss([
        { socket_drop: 1, queue_evicted: 10 },
        { socket_drop: 0, queue_evicted: null },
      ]),
    ).toEqual({
      measured: true,
      total: 11,
      evicted: 10,
      evictionMeasured: true,
    });
    expect(summariseLoss([{ socket_drop: 2 }])).toEqual({
      measured: true,
      total: 2,
      evicted: 0,
      evictionMeasured: false,
    });
  });
});

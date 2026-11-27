import { describe, expect, it } from "vitest";
import { diskChip, fmtPowerOn } from "./disk-health";

const base = {
  disk_reported: true,
  disk_worst_severity: null,
  disk_smart_available_count: 1,
  disk_count: 1,
};

describe("diskChip (#4731)", () => {
  it("has no chip for a node that never reported", () => {
    expect(diskChip({ ...base, disk_reported: false })).toBeNull();
  });
  it("shows a VM's SMART-less disks as n/a, never ok", () => {
    const chip = diskChip({ ...base, disk_smart_available_count: 0 });
    expect(chip?.label).toBe("disk: n/a");
    expect(chip?.className).not.toContain("emerald");
  });
  it("is green only with a verdict and no findings", () => {
    expect(diskChip(base)?.label).toBe("disk: ok");
  });
  it("maps severities", () => {
    expect(diskChip({ ...base, disk_worst_severity: "critical" })?.label).toBe(
      "disk: failing",
    );
    expect(diskChip({ ...base, disk_worst_severity: "warning" })?.label).toBe(
      "disk: attention",
    );
  });
  it("formats power-on hours", () => {
    expect(fmtPowerOn(null)).toBe("—");
    expect(fmtPowerOn(5)).toBe("5 h");
  });
});

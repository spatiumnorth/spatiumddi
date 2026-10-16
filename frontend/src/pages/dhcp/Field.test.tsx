/**
 * @vitest-environment jsdom
 *
 * The shared DHCP form Field (#1994): its visible label names exactly one
 * thing, whatever shape the children take, and it never overrides an id the
 * caller already set.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

import { Field } from "./_shared";

afterEach(cleanup);

describe("Field", () => {
  it("labels a lone input", () => {
    render(
      <Field label="Name">
        <input />
      </Field>,
    );
    expect(screen.getByLabelText("Name").tagName).toBe("INPUT");
  });

  it("keeps an id the caller set", () => {
    render(
      <Field label="Name">
        <input id="mine" />
      </Field>,
    );
    expect(screen.getByLabelText("Name").id).toBe("mine");
  });

  it("labels the input beside a datalist, without a wrapper", () => {
    const { container } = render(
      <Field label="IP Address">
        <input list="hint" />
        <datalist id="hint">
          <option value="10.0.0.1" />
        </datalist>
      </Field>,
    );
    expect(screen.getByLabelText("IP Address").tagName).toBe("INPUT");
    expect(container.querySelector("datalist")!.id).toBe("hint");
    expect(container.querySelector('[role="group"]')).toBeNull();
  });

  it("labels the input beside a conditional error line", () => {
    const Hostname = ({ err }: { err: string | null }) => (
      <Field label="Hostname">
        <input />
        {err && <p>{err}</p>}
      </Field>
    );
    const { rerender } = render(<Hostname err={null} />);
    const input = screen.getByLabelText("Hostname");
    expect(input.tagName).toBe("INPUT");
    rerender(<Hostname err="bad" />);
    // Same node: the error line appearing does not remount the input.
    expect(screen.getByLabelText("Hostname")).toBe(input);
    expect(screen.getByText("bad")).toBeTruthy();
  });

  it("labels a non-control child as a group", () => {
    render(
      <Field label="Scopes">
        <div>
          <label>
            <input type="checkbox" /> a
          </label>
        </div>
      </Field>,
    );
    expect(screen.getByLabelText("Scopes").getAttribute("role")).toBe("group");
  });

  it("labels two controls as a group rather than picking one", () => {
    render(
      <Field label="Range">
        <input />
        <input />
      </Field>,
    );
    expect(screen.getAllByLabelText("Range")).toHaveLength(1);
    expect(screen.getByLabelText("Range").getAttribute("role")).toBe("group");
  });
});

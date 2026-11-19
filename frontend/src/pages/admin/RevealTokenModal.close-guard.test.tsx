/**
 * @vitest-environment jsdom
 *
 * #3222: the token is shown once, so closing the reveal dialog without
 * having copied or revealed it asks first.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import type { ApiTokenCreated } from "@/lib/api";
import { RevealTokenModal } from "./ApiTokensPage";

const copyMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/clipboard", () => ({ copyToClipboard: copyMock }));

const TOKEN = {
  id: "tok-1",
  name: "ci-runner",
  prefix: "sddi_abcde",
  token: "sddi_abcdefghijklmnop",
} as unknown as ApiTokenCreated;

const WARNING = /haven't copied or revealed this token/;

beforeEach(() => copyMock.mockReset());
afterEach(cleanup);

function setup() {
  const onClose = vi.fn();
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <RevealTokenModal token={TOKEN} onClose={onClose} />
    </QueryClientProvider>,
  );
  return onClose;
}

const done = () => screen.getByRole("button", { name: /I've copied it/ });

describe("RevealTokenModal close guard", () => {
  it("asks before closing when nothing was copied or revealed", () => {
    const onClose = setup();
    fireEvent.click(done());
    expect(screen.getByText(WARNING)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("Go back keeps the dialog open and has focus", () => {
    const onClose = setup();
    fireEvent.click(done());
    const back = screen.getByRole("button", { name: "Go back" });
    expect(document.activeElement).toBe(back);
    fireEvent.click(back);
    expect(screen.queryByText(WARNING)).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
    expect(done()).toBeTruthy();
  });

  it("Close without copying closes", () => {
    const onClose = setup();
    fireEvent.click(done());
    fireEvent.click(
      screen.getByRole("button", { name: "Close without copying" }),
    );
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes directly after a successful copy", async () => {
    copyMock.mockResolvedValue(true);
    const onClose = setup();
    fireEvent.click(screen.getByTitle("Copy to clipboard"));
    await waitFor(() => screen.getByRole("button", { name: /Copied/ }));
    fireEvent.click(screen.getByRole("button", { name: /Copied/ }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(WARNING)).toBeNull();
  });

  it("closes directly after revealing the token", () => {
    const onClose = setup();
    fireEvent.click(screen.getByTitle("Reveal"));
    fireEvent.click(done());
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes directly after revealing the enrolment QR", () => {
    const onClose = setup();
    fireEvent.click(screen.getByText(/Show enrolment QR code/));
    fireEvent.click(done());
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("Esc asks first", () => {
    const onClose = setup();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.getByText(WARNING)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("the X button asks first", () => {
    const onClose = setup();
    fireEvent.click(screen.getByLabelText("Close dialog"));
    expect(screen.getByText(WARNING)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("a failed copy does not count as copied", async () => {
    copyMock.mockResolvedValue(false);
    const onClose = setup();
    fireEvent.click(screen.getByTitle("Copy to clipboard"));
    await waitFor(() => screen.getByText(/Automatic copy failed/));
    fireEvent.click(done());
    expect(screen.getByText(WARNING)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });
});

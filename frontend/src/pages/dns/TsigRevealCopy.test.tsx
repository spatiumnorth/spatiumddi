/**
 * @vitest-environment jsdom
 *
 * #1837: the TSIG reveal modal called the secret "hashed at rest". It is
 * Fernet-encrypted (SpatiumDDI must read it back to sign DNS updates), so a
 * hash claim is false and tells an operator the product cannot reuse it.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";

const { RevealedSecretModal } = await import("./DNSPage");

afterEach(cleanup);

describe("TSIG secret reveal copy", () => {
  it("does not claim the secret is hashed or unrecoverable", () => {
    render(
      <RevealedSecretModal
        name="k1"
        algorithm="hmac-sha256"
        secret="c2VjcmV0"
        action="created"
        onClose={() => {}}
      />,
    );
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/hashed/i);
    expect(text).not.toMatch(/can't be recovered/i);
    expect(text).toMatch(/encrypted/i);
  });
});

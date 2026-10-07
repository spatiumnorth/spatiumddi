import { useMemo } from "react";

import { buildQrMatrix, type QrLevel } from "@/lib/qr";
import { cn } from "@/lib/utils";

/**
 * QR code rendered as inline SVG (issue #906).
 *
 * SVG rather than a canvas or a data-URI `<img>`: it stays sharp at any size
 * and on any DPI, which matters because the thing reading it is a handheld
 * camera at an arbitrary distance and angle. It also needs no `img-src data:`
 * in the CSP.
 *
 * The matrix construction lives in `@/lib/qr` so it can be tested.
 */

export interface QrCodeProps {
  value: string;
  /** Rendered edge length in px. The matrix scales to fit. */
  size?: number;
  /**
   * Error-correction level. `M` (~15% recoverable) is the default because
   * these are read off a screen rather than a scuffed sticker, and a higher
   * level costs modules — which makes an already-long enrolment URI denser
   * and *harder* to scan, the opposite of the intent.
   */
  level?: QrLevel;
  className?: string;
  title?: string;
}

export function QrCode({
  value,
  size = 224,
  level = "M",
  className,
  title = "QR code",
}: QrCodeProps) {
  // `buildQrMatrix` throws when the payload exceeds what a QR code can hold
  // (qrcode-generator: "code length overflow"). Letting that escape a render
  // unwinds to the app-level ErrorBoundary and takes the whole page with it —
  // and its callers are reveal-once screens (the API token, the MFA
  // enrolment secret), so a crash there loses a credential that can never be
  // shown again.
  const result = useMemo(() => {
    try {
      return { matrix: buildQrMatrix(value, level) };
    } catch (err) {
      return {
        error:
          err instanceof Error && err.message
            ? err.message
            : "This value is too long to encode as a QR code.",
      };
    }
  }, [value, level]);

  if (!result.matrix) {
    return (
      <div
        role="img"
        aria-label={title}
        className={cn(
          "flex items-center justify-center rounded-md border border-dashed p-3 text-center text-xs text-muted-foreground",
          className,
        )}
        style={{ width: size, height: size }}
      >
        {result.error}
      </div>
    );
  }
  const matrix = result.matrix;

  return (
    <svg
      // The viewBox is in MODULE units with the quiet zone inside it, so the
      // margin scales with the code rather than being a CSS afterthought a
      // parent's padding could eat.
      viewBox={`0 0 ${matrix.extent} ${matrix.extent}`}
      width={size}
      height={size}
      className={className}
      role="img"
      aria-label={title}
      shapeRendering="crispEdges"
    >
      <title>{title}</title>
      {/* Explicit white ground. A QR code inheriting a dark-mode background
          is unscannable, so these render light-on-white whatever theme the
          operator is using. */}
      <rect width={matrix.extent} height={matrix.extent} fill="#ffffff" />
      <path d={matrix.d} fill="#000000" />
    </svg>
  );
}

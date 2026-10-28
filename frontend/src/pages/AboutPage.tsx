import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { versionApi } from "@/lib/api";
import { useAuth } from "@/hooks/useAuth";

/**
 * About (#2895) — product, version, licence, company, source links, the full
 * NOTICE and the generated third-party notice lists.
 *
 * It lives OUTSIDE the authenticated shell on purpose: Apache-2.0 §4(d) wants
 * the NOTICE text in a display the product generates, and the licence text has
 * to reach anyone who is handed the software — including the person at the
 * login page, and an air-gapped site with no route to GitHub. So everything
 * here is static or already public:
 *
 *  - `/api/v1/version` is unauthenticated and the sidebar and login screen
 *    already read it. Only its `version` and `appliance_mode` are used here;
 *    the host-identifying appliance fields it withholds from anonymous callers
 *    are not touched.
 *  - NOTICE / LICENSE and the npm list are static files in the web tier
 *    (`/legal/*.txt`, `/third-party-licenses.txt`), copied there by the Vite build.
 *  - The Python list is one static file the API serves unauthenticated.
 *
 * A file that is not there (a `npm run dev` session, or an api run outside its
 * image) is reported as "not available in this build"; the SPA fallback would
 * otherwise answer the same URL with index.html and render markup as licence
 * text, so a text/html answer counts as absent.
 */

const PRODUCT = "SpatiumDDI";
const SOURCE_URL = "https://github.com/spatiumnorth/spatiumddi";
const DOCS_URL = "https://www.spatiumddi.com";
const PRIVACY_URL = "https://www.spatiumddi.com/PRIVACY.html";

export const LICENSE_PATH = "/legal/LICENSE.txt";
export const NOTICE_PATH = "/legal/NOTICE.txt";
export const NPM_LICENSES_PATH = "/third-party-licenses.txt";
export const PYTHON_LICENSES_PATH = "/api/v1/about/third-party/python";

type Loaded =
  | { state: "loading" }
  | { state: "ready"; text: string }
  | { state: "absent" };

/** Fetch a static text file; `absent` for any failure or an HTML fallback. */
async function loadText(path: string): Promise<Loaded> {
  try {
    const resp = await fetch(path, { headers: { Accept: "text/plain" } });
    const type = resp.headers.get("content-type") ?? "";
    if (!resp.ok || type.includes("text/html")) return { state: "absent" };
    const text = await resp.text();
    return text.trim() ? { state: "ready", text } : { state: "absent" };
  } catch {
    return { state: "absent" };
  }
}

function useStaticText(path: string): Loaded {
  const [value, setValue] = useState<Loaded>({ state: "loading" });
  useEffect(() => {
    let live = true;
    void loadText(path).then((v) => {
      if (live) setValue(v);
    });
    return () => {
      live = false;
    };
  }, [path]);
  return value;
}

function ExtLink({ href, children }: { href: string; children: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex min-w-0 items-center gap-1 text-primary [overflow-wrap:anywhere] hover:underline"
    >
      {children}
      <ExternalLink className="h-3 w-3" aria-hidden />
    </a>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2 rounded-lg border bg-card p-5">
      <h2 className="text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

export function AboutPage() {
  const { isAuthenticated } = useAuth();
  const { data: versionInfo } = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
    staleTime: 60 * 60 * 1000,
    retry: 1,
  });
  const version = versionInfo?.version ?? __APP_VERSION__;
  const applianceMode = versionInfo?.appliance_mode ?? false;
  const notice = useStaticText(NOTICE_PATH);

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-8">
        <Link
          to={isAuthenticated ? "/dashboard" : "/login"}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          {isAuthenticated ? "Back to the console" : "Back to sign in"}
        </Link>

        <header className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">About {PRODUCT}</h1>
          <p className="text-sm text-muted-foreground">
            Open-source DNS, DHCP and IP address management, by Spatium North.
          </p>
          <p
            className="break-all font-mono text-sm"
            data-testid="about-version"
          >
            Version {version}
          </p>
        </header>

        <Section title="Licence">
          <p className="text-sm">
            {PRODUCT} is licensed under the{" "}
            <a
              href={LICENSE_PATH}
              className="text-primary hover:underline"
              target="_blank"
              rel="noopener noreferrer"
            >
              Apache License, Version 2.0
            </a>
            . Copyright SpatiumDDI Contributors. Published by Spatium North.
          </p>
        </Section>

        <Section title="Links">
          <ul className="space-y-1 text-sm">
            <li>
              Source code: <ExtLink href={SOURCE_URL}>{SOURCE_URL}</ExtLink>
            </li>
            <li>
              Documentation: <ExtLink href={DOCS_URL}>{DOCS_URL}</ExtLink>
            </li>
            <li>
              <ExtLink href={PRIVACY_URL}>Privacy statement</ExtLink> — no
              telemetry, and the outbound connections the platform can make.
            </li>
          </ul>
        </Section>

        <Section title="Third-party notices">
          <p className="text-sm text-muted-foreground">
            Generated when each image is built, so they list what that build
            contains. The hand-written catalogue, with the rationale for each
            component, is{" "}
            <ExtLink href="https://www.spatiumddi.com/THIRD_PARTY.html">
              THIRD_PARTY
            </ExtLink>
            .
          </p>
          <ul className="space-y-1 text-sm">
            <li>
              <a
                href={NPM_LICENSES_PATH}
                className="text-primary hover:underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                Web UI libraries (npm)
              </a>
            </li>
            <li>
              <a
                href={PYTHON_LICENSES_PATH}
                className="text-primary hover:underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                Backend libraries (Python)
              </a>
            </li>
          </ul>
        </Section>

        <Section title="Appliance and GPL components">
          {applianceMode ? (
            <p className="text-sm" data-testid="about-gpl">
              This is the {PRODUCT} OS appliance. It includes GPL and LGPL
              components, notably the Debian userland and the Linux kernel and,
              when the BGP advertiser is enabled, FRRouting. Their corresponding
              source is available from Debian and from each upstream project,
              and on request from Spatium North through the source repository
              above. The licence of each component is listed in the notice
              below.
            </p>
          ) : (
            <p className="text-sm" data-testid="about-gpl">
              The {PRODUCT} OS appliance image includes GPL and LGPL components,
              notably the Debian userland and the Linux kernel and, when the BGP
              advertiser is enabled, FRRouting. Their corresponding source is
              available from Debian and from each upstream project, and on
              request from Spatium North through the source repository above.
              The licence of each component is listed in the notice below.
            </p>
          )}
        </Section>

        <Section title="Notice">
          {notice.state === "loading" && (
            <p className="text-sm text-muted-foreground">Loading…</p>
          )}
          {notice.state === "absent" && (
            <p
              className="text-sm text-muted-foreground"
              data-testid="about-notice-absent"
            >
              The NOTICE text is bundled when the image is built and is not
              available in this build. It is also at the top level of the{" "}
              <ExtLink href={SOURCE_URL}>source repository</ExtLink>.
            </p>
          )}
          {notice.state === "ready" && (
            <pre
              className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/40 p-3 font-mono text-xs"
              data-testid="about-notice"
            >
              {notice.text}
            </pre>
          )}
        </Section>
      </div>
    </div>
  );
}

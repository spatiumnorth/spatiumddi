// Fetches the OpenAPI document for /api/docs and /api/redoc (#2935).
//
// The document is signed-in only, and these pages cannot present a Bearer:
// the console keeps its access token in memory (#484), so a separate page
// never sees it. What they do share is the HttpOnly refresh cookie, which is
// path-scoped to /api/v1/auth. The page's spec URL sits under that path, so
// the browser sends the cookie and the server reads it WITHOUT rotating it.
//
// Deliberately not POST /api/v1/auth/refresh: a refresh rotates, which
// revokes the session the console tab's access token belongs to, and a
// console refresh racing this page's would log the operator out.
//
// With no session, the page says so and links to the sign-in page rather
// than rendering an empty viewer.
//
// A file rather than inline script: the web tier's policy is
// ``script-src 'self'`` (#1157). Sets one global, read by the init scripts.
window.SpatiumDocsAuth = (function () {
  const SIGN_IN = "Sign in to SpatiumDDI to view the API documentation.";

  // Resolves to {spec}, or {error} with a sentence for the reader.
  async function load(script) {
    let r;
    try {
      r = await fetch(script.dataset.openapiUrl, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
    } catch (e) {
      return { error: "The API documentation could not be loaded." };
    }
    if (r.status === 401 || r.status === 403) {
      return { error: SIGN_IN };
    }
    if (!r.ok) {
      return { error: "The API documentation could not be loaded (HTTP " + r.status + ")." };
    }
    return { spec: await r.json() };
  }

  // Text only, never markup: nothing here is meant to be parsed as HTML.
  function showMessage(target, script, message) {
    const p = document.createElement("p");
    p.style.fontFamily = "sans-serif";
    p.style.margin = "2rem";
    p.textContent = message + " ";
    const a = document.createElement("a");
    a.href = script.dataset.loginUrl;
    a.textContent = "Sign in";
    p.appendChild(a);
    target.replaceChildren(p);
  }

  return { load: load, showMessage: showMessage };
})();

// Fetches the OpenAPI document for /api/docs and /api/redoc (#2935).
//
// The document is signed-in only, and these pages cannot authenticate on
// their own: the console keeps its access token in memory (#484), so a
// separate page never sees it. What it does share is the HttpOnly refresh
// cookie, so this asks /api/v1/auth/refresh for a token (the silent refresh
// a second console tab performs on load) and fetches the spec with it. With
// no session, the page says so and links to the sign-in page rather than
// rendering an empty viewer.
//
// A file rather than inline script: the web tier's policy is
// ``script-src 'self'`` (#1157). Sets one global, read by the init scripts.
window.SpatiumDocsAuth = (function () {
  async function token(refreshUrl) {
    let r;
    try {
      r = await fetch(refreshUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
    } catch (e) {
      return null;
    }
    if (!r.ok) return null;
    const body = await r.json().catch(function () {
      return null;
    });
    return body && body.access_token ? body.access_token : null;
  }

  // Resolves to {spec, token}, or {error} with a sentence for the reader.
  async function load(script) {
    const data = script.dataset;
    const access = await token(data.refreshUrl);
    if (!access) {
      return { error: "Sign in to SpatiumDDI to view the API documentation." };
    }
    let r;
    try {
      r = await fetch(data.openapiUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json", Authorization: "Bearer " + access },
      });
    } catch (e) {
      return { error: "The API documentation could not be loaded." };
    }
    if (r.status === 401 || r.status === 403) {
      return { error: "Sign in to SpatiumDDI to view the API documentation." };
    }
    if (!r.ok) {
      return { error: "The API documentation could not be loaded (HTTP " + r.status + ")." };
    }
    return { spec: await r.json(), token: access };
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

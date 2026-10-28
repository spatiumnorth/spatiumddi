// Starts ReDoc on /api/redoc (#2935).
//
// FastAPI's get_redoc_html() points ReDoc at the spec with a ``spec-url``
// attribute and ReDoc fetches it itself, with no way to add a header. The
// document is signed-in only now, so api-docs-auth.js fetches it with a
// Bearer and ReDoc is started from the object. A file rather than inline
// script for the web tier's ``script-src 'self'`` (#1157).
(async function () {
  const script = document.currentScript;
  const target = document.getElementById("redoc-container");
  const loaded = await window.SpatiumDocsAuth.load(script);
  if (loaded.error) {
    window.SpatiumDocsAuth.showMessage(target, script, loaded.error);
    return;
  }
  Redoc.init(loaded.spec, {}, target);
})();

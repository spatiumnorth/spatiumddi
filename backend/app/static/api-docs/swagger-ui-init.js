// Starts Swagger UI on /api/docs (#1157).
//
// FastAPI's get_swagger_ui_html() writes this call into the page as an
// inline <script>, which the web tier's `script-src 'self'` refuses, so the
// page rendered blank through the web port. As a file of its own it loads
// like any other same-origin script. The options are FastAPI's defaults
// (fastapi.openapi.docs.swagger_ui_default_parameters); the URLs come from
// the page (app/api/docs.py).
//
// #2935 — the spec is signed-in only, so api-docs-auth.js fetches it with a
// Bearer and it is handed to Swagger UI as an object. "Try it out" sends the
// same token unless the operator authorises with another one.
(async function () {
  const script = document.currentScript;
  const target = document.getElementById("swagger-ui");
  const loaded = await window.SpatiumDocsAuth.load(script);
  if (loaded.error) {
    window.SpatiumDocsAuth.showMessage(target, script, loaded.error);
    return;
  }
  window.ui = SwaggerUIBundle({
    spec: loaded.spec,
    dom_id: "#swagger-ui",
    layout: "BaseLayout",
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    requestInterceptor: function (req) {
      if (!req.headers.Authorization) {
        req.headers.Authorization = "Bearer " + loaded.token;
      }
      return req;
    },
  });
})();

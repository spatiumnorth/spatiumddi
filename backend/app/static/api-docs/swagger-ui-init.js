// Starts Swagger UI on /api/docs (#1157).
//
// FastAPI's get_swagger_ui_html() writes this call into the page as an
// inline <script>, which the web tier's `script-src 'self'` refuses, so the
// page rendered blank through the web port. As a file of its own it loads
// like any other same-origin script. The options are FastAPI's defaults
// (fastapi.openapi.docs.swagger_ui_default_parameters); the spec URL comes
// from the page (app/api/docs.py), which knows the app's openapi_url.
const ui = SwaggerUIBundle({
  url: document.currentScript.dataset.openapiUrl,
  dom_id: "#swagger-ui",
  layout: "BaseLayout",
  deepLinking: true,
  showExtensions: true,
  showCommonExtensions: true,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
});

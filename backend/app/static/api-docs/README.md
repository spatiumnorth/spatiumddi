# API docs assets (vendored)

`/api/docs` (Swagger UI) and `/api/redoc` (ReDoc) are served by the api with
these files rather than FastAPI's default CDN links (#1157). The web tier's
Content-Security-Policy allows scripts and stylesheets from the page's own
origin only, and an air-gapped install cannot reach a CDN at all.
`app/api/docs.py` serves the pages and mounts this directory at
`/api/docs/static/`.

Both bundles are byte-for-byte copies of the published npm packages. Do not
edit them; bump them.

| Package | Files | License |
|---|---|---|
| `swagger-ui-dist@5.34.0` | `swagger-ui/swagger-ui-bundle.js`, `swagger-ui/swagger-ui.css` | Apache-2.0 (`swagger-ui/LICENSE`, `swagger-ui/NOTICE`) |
| `redoc@2.5.4` | `redoc/redoc.standalone.js` (from `bundles/`) | MIT (`redoc/LICENSE`) |

Each bundle's `*.LICENSE.txt` is the license text of the packages bundled
into it, which the bundle's first line points at. `swagger-ui-init.js`,
`redoc-init.js` and `api-docs-auth.js` are ours: the first two replace
FastAPI's inline initializers, and the third fetches the OpenAPI document
with a Bearer, since `/api/openapi.json` is signed-in only (#2935).

npm tarball integrity (`npm view <pkg>@<version> dist.integrity`):

- `swagger-ui-dist@5.34.0`: `sha512-H6tAIjr3XqE31PbkZl0OFya1ziRLDfTwh3J6OHdumPtPCLfjTnyLeagl/55kFNZcTOz9a9QI9WP0FXldwiGJag==`
- `redoc@2.5.4`: `sha512-M6jWhG1qoBnH6TFmzJnstyCZ87HmOY/UzDm78mHiYihEdlV/YcS9ogOo1NlElnJMeLsyxHFe2yFc4sNjHTrABQ==`

SHA-256 of the files as shipped:

```
3f6abf70480db7e07914df4c98a77385f22ea585eaf457a3e6415ba0eae2d167  swagger-ui/swagger-ui-bundle.js
c3cfe8248c4b0b89673600fb829924eafbac6de4bc4b2b06f5f5243483074d0a  swagger-ui/swagger-ui.css
dcaf76612bc4a3fbcc923a8966dee2f6146a5f32e5ce1b6f02dd60cbbf89500b  redoc/redoc.standalone.js
```

## Bumping

The versions are also pinned in `versions.json` (`swagger-ui`, `redoc`),
which `scripts/lint_versions.py` holds to this file and to
`docs/THIRD_PARTY.md`. Change the version in all three places and the hashes
above in the same commit:

```sh
cd "$(mktemp -d)"
npm pack swagger-ui-dist@<version> redoc@<version>   # npm checks each tarball's integrity
tar -xzf swagger-ui-dist-<version>.tgz && cp package/{swagger-ui-bundle.js,swagger-ui-bundle.js.LICENSE.txt,swagger-ui.css,LICENSE,NOTICE} <repo>/backend/app/static/api-docs/swagger-ui/ && rm -rf package
tar -xzf redoc-<version>.tgz && cp package/bundles/{redoc.standalone.js,redoc.standalone.js.LICENSE.txt} package/LICENSE <repo>/backend/app/static/api-docs/redoc/
```

Then load both pages through the web tier and check the browser console. The
policy the pages run under is `frontend/default.conf.template` (and
`charts/spatiumddi/templates/frontend-tls-config.yaml` on the appliance). A
new bundle that needs `eval`, an inline script or another origin will show
up there as a Content-Security-Policy violation.

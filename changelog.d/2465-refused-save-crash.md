### Fixed

- **A refused DNSSEC policy or DNS pool save no longer crashes the page
  (#2465).** The 422's `detail` is pydantic's list of error objects and
  both dialogs rendered it as a React child, so the route's error
  boundary replaced the page with "This page failed to load" and the
  operator never saw why. They now show the reason as text ("name: …")
  and stay open, through `formatApiError`, as do the IPAM import /
  export dialogs and the AI prompts form, which carried the same
  pattern.

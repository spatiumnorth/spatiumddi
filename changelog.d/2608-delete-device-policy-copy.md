### Fixed

  - **DHCP "Delete device policy" no longer says pools lose their class 
  (#2608).** Since #2285 the server refuses the delete (409) while a pool is 
  restricted to the policy's class, so the old sentence described an outcome 
  that cannot happen. The dialog now says such a policy cannot be deleted until 
  the restriction is cleared.

### Fixed

- A refused or failed request for an approval policy, change request, portal request, AI prompt or AI proposal that no longer exists answered with a bare `Not Found`, so the console's error line did not say what was missing. Those 404s now name the object ("Approval policy not found", "Change request not found", "Prompt not found" and so on), and a test fails any `HTTPException(404)` raised without a detail. (#4359)

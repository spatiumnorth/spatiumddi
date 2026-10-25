### Fixed

- **A request body that is not valid UTF-8 now gets a 422, not a 500 (#2677).**
  Sent with a missing, empty or non-JSON Content-Type, such a body made
  the validation-error handler itself fail while encoding the rejected
  input, so the client got an Internal Server Error and Diagnostics
  recorded an unhandled exception for what is a client mistake. The 422
  is the same response as before for every other input.

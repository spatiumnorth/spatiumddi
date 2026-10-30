### Fixed

- **Active Sessions opens a superadmin on "All users" however the page
  was reached (#3010).** Opened by URL, from a bookmark or by a reload,
  the page started a superadmin on "My sessions" and kept it there, so
  another user's live session was not listed: the scope was read once,
  before the signed-in user had loaded. The scope now follows the user
  until the operator picks one, and a pick is kept. The list waits until
  the page knows who is asking, and the scope toggle says which button
  is on.

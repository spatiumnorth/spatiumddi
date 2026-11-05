### Fixed

- Closing the new API token dialog returns keyboard focus to the New Token button even when the token was created with Enter in a form field, and a confirm that replaces a loading dialog (DNS Delete Server Group) returns focus to Delete Group even after a Tab moved focus inside the loading dialog. A dialog opened from inside another dialog that is still open returns focus into that dialog, never to the page behind it (#3483).

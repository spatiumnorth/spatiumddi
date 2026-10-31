### Fixed

- **API-token dialog no longer loses an uncopied token (#3222).**
  "I've copied it", Esc and the close button now ask "close anyway?"
  when the token was never copied or revealed, since it is shown
  only once. A copy that failed does not count as copied.

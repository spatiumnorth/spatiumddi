### Changed

- **Hover text now shows in about 300 ms (#4210).** The browser's own
  `title` tooltip waits about a second, so small icon buttons felt
  unlabelled. One app-wide tooltip now takes over every `title`: it
  appears after 300 ms on hover and at once on keyboard focus, hides on
  Esc, blur, scroll or click, stays on screen, follows the light and dark
  themes, and still shows the reason on a disabled button.

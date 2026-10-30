### Fixed

- The BIND9 tab of the DNS import page and the Kea and ISC tabs of the DHCP import page now upload the chosen file as a form upload. Preview import sent it as JSON with no file in it, so the server refused it, and the page then crashed on the refusal instead of showing it. Every error on those pages is now shown as a message.

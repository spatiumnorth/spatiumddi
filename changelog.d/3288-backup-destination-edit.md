### Fixed

- **Editing a backup destination is held to the bounds Add holds it to,
  and can take a stored secret away (#3288, #3289).** An empty name, a
  name over 120 characters or a description over 500 is now refused
  with a 422 naming the field, and a null on a required field leaves it
  as it was instead of answering 500. Moving an Azure destination to
  an account key (or an SCP one between password and key, or an HTTPS
  PUT one to auth `none`) now drops the credential it left, and naming
  both Azure or SCP modes in one edit is refused. Through the API, a
  `null` for a secret field clears it, and a `null` for the whole
  `config` leaves it as it was instead of answering 500. The Edit dialog
  shows "(set ...)" on a secret only when one is stored.

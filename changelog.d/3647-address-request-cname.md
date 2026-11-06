### Fixed

- An address request whose host name already holds a CNAME in the subnet's DNS zone is now refused at submit, in words, instead of promising an "A" record the approval would never write; the approval re-checks it, so a CNAME added after submit fails the request the same way (#3647).

### Fixed

- Global search no longer answers no results when 100 or more addresses (or DNS records) under a trashed subnet (or zone) match first: trashed parents are now excluded in SQL before the per-type fetch cap, instead of after it (#3825).

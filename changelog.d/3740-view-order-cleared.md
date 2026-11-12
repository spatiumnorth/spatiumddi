### Fixed

- DNS: Edit View and New View refuse a cleared Order instead of silently saving it as 0, which moved the view ahead of every view ordered 1 and up; the field now says it is a whole number, 0 or higher, lowest evaluated first (#3740).

#!/bin/sh
#
# Checks that the index of the man pages links to every page
#

srcdir="${ABS_SRCDIR:-.}"
r=0

for page in "${srcdir}"/man/*.txt; do
	name="$(basename "${page}" .txt)"

	# The index does not link to itself
	if [ "${name}" = "index" ]; then
		continue
	fi

	if ! grep -q "^link:${name}\[[0-9]\]::$" "${srcdir}/man/index.txt"; then
		echo "man/index.txt does not link to ${name}" >&2
		r=1
	fi
done

exit ${r}

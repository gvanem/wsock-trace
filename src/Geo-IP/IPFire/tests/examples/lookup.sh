#!/bin/sh
#
# Runs the example that shows how to look up addresses, so that it keeps working
#

set -e

lookup="${ABS_BUILDDIR:-.}/examples/c/lookup"

# Look up an address that is in the database
output="$("${lookup}" "${TEST_DATABASE}" 81.3.27.38)"

case "${output}" in
	"81.3.27.38: 81.3.0.0/"*)
		;;

	*)
		echo "Unexpected output: ${output}" >&2
		exit 1
		;;
esac

# Look up an address that is not in the database
output="$("${lookup}" "${TEST_DATABASE}" 10.0.0.1)"

if [ "${output}" != "10.0.0.1: Not found" ]; then
	echo "Unexpected output: ${output}" >&2
	exit 1
fi

# Anything that is not an address must fail
if "${lookup}" "${TEST_DATABASE}" nonsense 2>/dev/null; then
	echo "Looking up an invalid address did not fail" >&2
	exit 1
fi

exit 0

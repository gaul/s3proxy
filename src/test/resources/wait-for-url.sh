#!/bin/bash

# Wait for a URL to answer HTTP, for use after starting a service in the
# background.  Any status counts: a probe that carries no credentials often
# draws a 4xx, and what matters is that the service is answering rather than
# what it answers.  Running out of time exits non-zero so that a caller stops
# instead of testing against a service that never came up.
#
# usage: wait-for-url.sh URL [SECONDS]

set -o errexit
set -o nounset

if (($# < 1)); then
    echo "usage: $0 URL [SECONDS]" >&2
    exit 2
fi

url="$1"
timeout="${2:-30}"

for i in $(seq "${timeout}"); do
    if curl --silent --output /dev/null "${url}"; then
        exit 0
    fi
    if [ "${i}" -eq "${timeout}" ]; then
        echo "${url} did not answer within ${timeout} seconds" >&2
        exit 1
    fi
    sleep 1
done

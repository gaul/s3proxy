#!/bin/bash

set -o errexit
set -o nounset

# Optional first argument selects a config; remaining args pass through to pytest via tox.
# Example single test: ./src/test/resources/run-s3-tests.sh s3proxy-localstack.conf \
#     s3tests_boto3/functional/test_s3.py::test_bucket_list_delimiter_prefix
S3PROXY_CONF="s3proxy.conf"
if (($# > 0)) && [[ "$1" == *.conf ]]; then
    S3PROXY_CONF="$1"
    shift
fi

if (($# > 0)) && [[ "$1" == -- ]]; then
    shift
fi

S3PROXY_BIN="${PWD}/target/s3proxy"
S3PROXY_PORT="${S3PROXY_PORT:-8081}"
export S3TEST_CONF="${PWD}/src/test/resources/s3-tests.conf"
TOX_TEST_ARGS=("$@")
# JUnit XML names the tests that failed, where the console output leaves a
# count and a scroll of output to search.  It is named after the config since
# several lanes run one after another, and absolute because pytest runs from
# the submodule.
S3PROXY_JUNIT_XML="${PWD}/target/s3-tests-${S3PROXY_CONF%.conf}.xml"

# launch S3Proxy using HTTP and a fixed port
sed "s,^\(s3proxy.endpoint\)=.*,\1=http://127.0.0.1:${S3PROXY_PORT}," \
        < "src/test/resources/$S3PROXY_CONF" | grep -v secure-endpoint > target/s3proxy.conf
S3PROXY_LOG="${PWD}/target/s3proxy.log"
java -DLOG_LEVEL=${LOG_LEVEL:-info} -jar $S3PROXY_BIN --properties target/s3proxy.conf > "$S3PROXY_LOG" 2>&1 &
S3PROXY_PID=$!

function finish {
    rc=$?
    if [ "$rc" -ne 0 ] && [ -s "$S3PROXY_LOG" ]; then
        echo "===== last 200 lines of s3proxy.log (script exit $rc) =====" >&2
        tail -200 "$S3PROXY_LOG" >&2
        echo "===== end of s3proxy.log =====" >&2
    fi
    kill "$S3PROXY_PID" 2>/dev/null || true
}
trap finish EXIT

# Wait for S3Proxy to become ready.  /healthz answers without authentication
# and is served by the request handler, so a 200 shows the handler answering
# rather than only that the port is bound.  The service path, if the config
# sets one, prefixes it just as it does every other request.
healthz="http://127.0.0.1:${S3PROXY_PORT}"
service_path=$(sed -n 's,^s3proxy\.service-path=,,p' target/s3proxy.conf)
if [ -n "${service_path}" ]; then
    healthz="${healthz}/${service_path#/}"
fi
healthz="${healthz}/healthz"

# Give up rather than run the suite against a proxy that never came up: every
# test would fail with a connection error that says nothing about the cause.
for i in $(seq 30); do
    if curl --silent --fail --output /dev/null "${healthz}"; then
        break
    fi
    if ! kill -0 "${S3PROXY_PID}" 2>/dev/null; then
        echo "s3proxy exited before answering ${healthz}" >&2
        exit 1
    fi
    if [ "${i}" -eq 30 ]; then
        echo "s3proxy did not answer ${healthz} within ${i} seconds" >&2
        exit 1
    fi
    sleep 1
done

# The fails_on_s3proxy markers are deliberately absent: s3-tests/conftest.py
# turns them into strict expected failures instead, so a test that starts
# passing fails the suite rather than going on being skipped unnoticed.  The
# tags below deselect whole unimplemented features, which is not worth running
# to watch fail.
tags='not appendobject'\
' and not bucket_logging'\
' and not bucket_policy'\
' and not cors'\
' and not encryption'\
' and not fails_strict_rfc2616'\
' and not iam_tenant'\
' and not lifecycle'\
' and not object_attributes'\
' and not object_lock'\
' and not object_ownership'\
' and not policy'\
' and not policy_status'\
' and not s3control'\
' and not s3select'\
' and not s3website'\
' and not sse_s3'\
' and not tagging'\
' and not test_of_sts'\
' and not user_policy'\
' and not versioning'\
' and not webidentity_test'

backend=""
if [ "${S3PROXY_CONF}" = "s3proxy-azurite.conf" ]; then
    backend="azureblob"
elif [ "${S3PROXY_CONF}" = "s3proxy-fake-gcs-server.conf" ]; then
    backend="gcs"
elif [ "${S3PROXY_CONF}" = "s3proxy-swift.conf" ]; then
    backend="swift"
elif [[ "${S3PROXY_CONF}" == s3proxy-localstack*.conf ]]; then
    backend="localstack"
    tags="${tags} and not fails_on_aws"
elif [[ "${S3PROXY_CONF}" == s3proxy-*-nio2.conf ]] ||
        [[ "${S3PROXY_CONF}" == s3proxy.conf ]]; then
    # s3proxy.conf defaults to the transient backend.
    backend="nio2"
fi

# execute s3-tests.  FORCE_COLOR is unset because a value other than 0 or 1 --
# which some terminals and CI runners set -- makes tox reject its own
# arguments.
pushd s3-tests
env -u FORCE_COLOR tox -- -m "${tags}" --s3proxy-backend="${backend}" \
        --junitxml="${S3PROXY_JUNIT_XML}" "${TOX_TEST_ARGS[@]}"

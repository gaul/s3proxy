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
# Answer every request's first attempt.  botocore treats BadDigest and 500
# as transient and retries them with exponential backoff, so each test that
# deliberately provokes one -- the checksum mismatches, the marked delimiter
# listings -- slept through five attempts, about a minute of the lane in
# total.  The proxy is local: nothing between the client and it is
# transient, and every test asserts on an answer the first attempt already
# carries.  tox passes these through via passenv.
export AWS_MAX_ATTEMPTS=1
export AWS_RETRY_MODE=standard
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

# Admits the server-side encryption tests on a lane whose store encrypts:
# the sse_s3 tag and the encryption tag whole, whose remainder beyond
# SSE-S3 is SSE-C, answered now on the same stores.  That includes the
# bucket_encryption tests, which ask a bucket to encrypt by default
# through the ?encryption subresource these stores now answer.
enable_sse_tests() {
    tags="${tags/ and not sse_s3/}"
    tags="${tags/ and not encryption/}"
}

backend=""
# A -k expression for tests a marker cannot describe, empty for most lanes.
deselect_by_name=""
if [ "${S3PROXY_CONF}" = "s3proxy-azurite.conf" ]; then
    backend="azureblob"
elif [ "${S3PROXY_CONF}" = "s3proxy-fake-gcs-server.conf" ]; then
    backend="gcs"
elif [ "${S3PROXY_CONF}" = "s3proxy-swift.conf" ]; then
    backend="swift"
elif [[ "${S3PROXY_CONF}" == s3proxy-localstack*.conf ]]; then
    backend="localstack"
    # fails_on_aws marks what real S3 refuses, and this lane used to deselect
    # the tag on the reasoning that LocalStack emulates S3.  It is more
    # permissive than S3 in places, though, so a good number of them pass;
    # the markers record the ones that do not.  Deselecting the tag hid the
    # conditional writes that only this lane sends to a service that answers
    # them natively.
    # The aws-s3 backend passes versioning through to a service that has it,
    # so run the tests for it here as well as on the transient lane.  This is
    # the only lane that covers the pass-through path.
    tags="${tags/ and not versioning/}"
    # The same goes for server-side encryption: LocalStack encrypts, so the
    # SSE tests exercise the pass-through here rather than watching a
    # store that cannot encrypt refuse it.
    enable_sse_tests
    # Five threads delete the same versions at once and each expects to have
    # deleted them all.  LocalStack refuses a version it no longer has, where
    # S3 counts deleting one that is already gone as a success -- so whether
    # this passes depends on whether the threads overlap.  Neither expecting
    # a pass nor expecting a failure describes it, which is what a marker
    # would have to do.
    deselect_by_name="not test_versioning_concurrent_multi_object_delete"
elif [ "${S3PROXY_CONF}" = "s3proxy-filesystem.conf" ] ||
        [ "${S3PROXY_CONF}" = "s3proxy.conf" ]; then
    # s3proxy.conf defaults to the transient backend.
    # Both nio2 stores, named apart as well so that a test can record a
    # limitation of one: they share almost everything and part company over
    # versioning.
    if [ "${S3PROXY_CONF}" = "s3proxy.conf" ]; then
        backend="nio2,transient"
        # The transient store implements object versioning, so run the tests
        # for it rather than deselecting them.  The filesystem store shares
        # the code but reports supportsVersioning() == false, since its
        # versions would outlive the process and settle a layout S3Proxy
        # would owe its users; there the requests are still 501.
        tags="${tags/ and not versioning/}"
        # Server-side encryption parts the two stores on the same line: the
        # transient store answers the header families, since what it holds
        # never rests anywhere a caller could read it, while the filesystem
        # store would be reporting AES256 over plaintext on a real disk and
        # answers 501 instead.  So these run here and not below.
        enable_sse_tests
    else
        backend="nio2,filesystem"
    fi
fi

# execute s3-tests.  FORCE_COLOR is unset because a value other than 0 or 1 --
# which some terminals and CI runners set -- makes tox reject its own
# arguments.
pushd s3-tests
deselect_args=()
if [ -n "${deselect_by_name}" ]; then
    deselect_args=(-k "${deselect_by_name}")
fi
env -u FORCE_COLOR tox -- -m "${tags}" --s3proxy-backend="${backend}" \
        ${deselect_args[@]+"${deselect_args[@]}"} \
        --junitxml="${S3PROXY_JUNIT_XML}" \
        ${TOX_TEST_ARGS[@]+"${TOX_TEST_ARGS[@]}"}

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

# Creates a KMS key on the service the aws-s3 backend reaches and prints its
# ARN.  The request is signed with the backend's own credentials and region,
# so the key lands in the account S3Proxy's writes are made from.
create_kms_key() {
    local endpoint identity credential region response
    endpoint=$(sed -n 's,^jclouds\.endpoint=,,p' target/s3proxy.conf)
    identity=$(sed -n 's,^jclouds\.identity=,,p' target/s3proxy.conf)
    credential=$(sed -n 's,^jclouds\.credential=,,p' target/s3proxy.conf)
    region=$(sed -n 's,^jclouds\.region=,,p' target/s3proxy.conf)
    response=$(curl --silent --show-error \
            --aws-sigv4 "aws:amz:${region:-us-east-1}:kms" \
            --user "${identity}:${credential}" \
            --header 'Content-Type: application/x-amz-json-1.1' \
            --header 'X-Amz-Target: TrentService.CreateKey' \
            --data '{}' "${endpoint%/}/") || true
    if ! python3 -c 'import json, sys
print(json.load(sys.stdin)["KeyMetadata"]["Arn"])' <<< "${response}"; then
        echo "could not create a KMS key at ${endpoint}: ${response}" >&2
        return 1
    fi
}

# The SSE-KMS tests encrypt with the two key ids s3-tests.conf names.  S3
# refuses a key that does not exist, KMS.NotFoundException, and MiniStack
# does too since 1.5.43, so a lane whose service encrypts creates two real
# keys and hands the tests a copy of the conf that names them.
use_created_kms_keys() {
    local key1 key2
    key1=$(create_kms_key)
    key2=$(create_kms_key)
    sed -e "s,^kms_keyid *=.*,kms_keyid = ${key1}," \
            -e "s,^kms_keyid2 *=.*,kms_keyid2 = ${key2}," \
            < "${S3TEST_CONF}" > target/s3-tests.conf
    export S3TEST_CONF="${PWD}/target/s3-tests.conf"
}

backend=""
# A -k expression for tests a marker cannot describe, empty for most lanes.
deselect_by_name=""
if [ "${S3PROXY_CONF}" = "s3proxy-azurite.conf" ]; then
    backend="azureblob"
elif [ "${S3PROXY_CONF}" = "s3proxy-azurite-versioning.conf" ]; then
    # The azureblob store versioned: every container reports Enabled and
    # Suspended answers NotImplemented, so what that leaves unanswered
    # carries a marker of its own, alongside the azureblob ones.
    backend="azureblob,azureblob_versioning"
    tags="${tags/ and not versioning/}"
elif [ "${S3PROXY_CONF}" = "s3proxy-fake-gcs-server.conf" ]; then
    backend="gcs"
    # The google-cloud-storage backend translates versioning onto GCS
    # generations, and fake-gcs-server's memory backend keeps archived
    # generations, so the tests run here; what the translation cannot
    # express -- Suspended, null versions -- carries markers.
    tags="${tags/ and not versioning/}"
elif [ "${S3PROXY_CONF}" = "s3proxy-swift.conf" ]; then
    backend="swift"
elif [[ "${S3PROXY_CONF}" == s3proxy-ministack*.conf ]]; then
    # MiniStack reaches the same aws-s3 backend as the LocalStack lane, but
    # it is a different emulator and does not share every gap that lane's
    # markers record, so it answers to markers of its own.  The glob takes a
    # conf of one's own as well, for a MiniStack reached somewhere else.
    backend="ministack"
    # Versioning and server-side encryption pass through to a service that
    # has both, as they do on the LocalStack lane.
    tags="${tags/ and not versioning/}"
    enable_sse_tests
    use_created_kms_keys
    # Object lock passes through as well, and MiniStack keeps the locks,
    # with the gaps its markers record.
    tags="${tags/ and not object_lock/}"
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
    use_created_kms_keys
    # Object lock passes through as well, and LocalStack keeps the locks.
    # This lane and MiniStack's are the ones that run the tag: the other
    # stores answer the lock 501.
    tags="${tags/ and not object_lock/}"
    # Five threads delete the same versions at once and each expects to have
    # deleted them all.  LocalStack refuses a version it no longer has, where
    # S3 counts deleting one that is already gone as a success -- so whether
    # this passes depends on whether the threads overlap.  Neither expecting
    # a pass nor expecting a failure describes it, which is what a marker
    # would have to do.
    #
    # LocalStack refuses a CopyObject whose If-Match fails, 412, and on an
    # unversioned bucket overwrites the destination's content anyway, as it
    # does when asked directly.  The parametrized test passes on a versioned
    # bucket and fails on the other, which one marker cannot say either.
    deselect_by_name="not test_versioning_concurrent_multi_object_delete"
    deselect_by_name+=" and not test_copy_object_dest_if_match"
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
rc=0
env -u FORCE_COLOR tox -- -m "${tags}" --s3proxy-backend="${backend}" \
        ${deselect_args[@]+"${deselect_args[@]}"} \
        --junitxml="${S3PROXY_JUNIT_XML}" \
        ${TOX_TEST_ARGS[@]+"${TOX_TEST_ARGS[@]}"} || rc=$?
popd

# On GitHub Actions, put the counts and the names of any test that broke on
# the run's summary page.  A summary that cannot be written does not change
# the lane's result.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    lane="${S3PROXY_CONF%.conf}"
    lane="${lane#s3proxy-}"
    if [ "${lane}" = "s3proxy" ]; then
        lane="transient"
    fi
    python3 -I src/test/resources/s3-tests-summary.py \
            "${lane}" "${S3PROXY_JUNIT_XML}" \
            >> "${GITHUB_STEP_SUMMARY}" || true
fi
exit "${rc}"

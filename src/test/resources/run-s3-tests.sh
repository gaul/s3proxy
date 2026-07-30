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

# wait for S3Proxy to start
for i in $(seq 30);
do
    if exec 3<>"/dev/tcp/localhost/${S3PROXY_PORT}";
    then
        exec 3<&-  # Close for read
        exec 3>&-  # Close for write
        break
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
    # s3proxy.conf defaults to the transient-nio2 backend.
    backend="nio2"
fi

# execute s3-tests.  FORCE_COLOR is unset because a value other than 0 or 1 --
# which some terminals and CI runners set -- makes tox reject its own
# arguments.
pushd s3-tests
env -u FORCE_COLOR tox -- -m "${tags}" --s3proxy-backend="${backend}" \
        "${TOX_TEST_ARGS[@]}"

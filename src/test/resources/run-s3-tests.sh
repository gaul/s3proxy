#!/bin/bash

set -o errexit
set -o nounset

S3PROXY_BIN="${PWD}/target/s3proxy"
S3PROXY_PORT="${S3PROXY_PORT:-8081}"
export S3TEST_CONF="${PWD}/src/test/resources/s3-tests.conf"

# launch S3Proxy using HTTP and a fixed port
sed "s,^\(s3proxy.endpoint\)=.*,\1=http://127.0.0.1:${S3PROXY_PORT}," \
        < src/test/resources/s3proxy.conf | grep -v secure-endpoint > target/s3proxy.conf
$S3PROXY_BIN --properties target/s3proxy.conf &
S3PROXY_PID=$!

function finish {
    kill $S3PROXY_PID
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

# execute s3-tests
pushd s3-tests
tox -- -m 'not fails_on_s3proxy and not appendobject and not bucket_policy and not checksum and not cors and not encryption and not fails_strict_rfc2616 and not iam_tenant and not lifecycle and not object_lock and not policy and not policy_status and not s3select and not s3website and not sse_s3 and not tagging and not test_of_sts and not user_policy and not versioning and not webidentity_test'

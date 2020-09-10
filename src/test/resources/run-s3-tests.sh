#!/bin/bash

set -o errexit
set -o nounset

S3PROXY_BIN="${PWD}/target/s3proxy"
S3PROXY_PORT="${S3PROXY_PORT:-8081}"
export S3TEST_CONF="${PWD}/src/test/resources/s3-tests.conf"

# configure s3-tests
pushd s3-tests
./bootstrap
popd

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
./virtualenv/bin/nosetests -a '!fails_on_s3proxy,!appendobject,!bucket-policy,!cors,!encryption,!fails_strict_rfc2616,!lifecycle,!object-lock,!policy,!policy_status,!s3select,!s3website,!tagging,!user-policy,!versioning'

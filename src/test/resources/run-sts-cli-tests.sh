#!/usr/bin/env bash
# End-to-end check of STS GetFederationToken with the stock AWS CLI: start
# S3Proxy with STS enabled, mint scoped temporary credentials, and confirm
# that what the session policy allows works and everything else is refused.
#
# Usage: ./src/test/resources/run-sts-cli-tests.sh
# Requires the aws CLI on PATH and a built jar (mvn package -DskipTests).

set -o errexit
set -o nounset
set -o pipefail

PORT=${S3PROXY_STS_PORT:-18080}
ENDPOINT="http://127.0.0.1:${PORT}"
S3PROXY_BIN="${PWD}/target/s3proxy"
WORK=$(mktemp -d)
LOG="${WORK}/s3proxy.log"

cat > "${WORK}/s3proxy.conf" <<EOF
s3proxy.endpoint=${ENDPOINT}
s3proxy.authorization=aws-v4
s3proxy.identity=parent-identity
s3proxy.credential=parent-credential
s3proxy.sts.enabled=true
jclouds.provider=transient
jclouds.identity=remote-identity
jclouds.credential=remote-credential
EOF

java -jar "${S3PROXY_BIN}" --properties "${WORK}/s3proxy.conf" \
    > "${LOG}" 2>&1 &
S3PROXY_PID=$!

function finish {
    rc=$?
    if [ "${rc}" -ne 0 ]; then
        echo "===== s3proxy.log =====" >&2
        tail -100 "${LOG}" >&2
    fi
    kill "${S3PROXY_PID}" 2>/dev/null || true
    rm -rf "${WORK}"
}
trap finish EXIT

for i in $(seq 30); do
    if curl --silent --fail --output /dev/null "${ENDPOINT}/healthz"; then
        break
    fi
    if [ "${i}" -eq 30 ]; then
        echo "s3proxy did not start" >&2
        exit 1
    fi
    sleep 1
done

export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
# Presign with SigV4, which temporary credentials require; AWS CLI v1
# otherwise presigns S3 URLs with SigV2.
cat > "${WORK}/aws-config" <<EOF
[default]
s3 =
    signature_version = s3v4
EOF
export AWS_CONFIG_FILE="${WORK}/aws-config"
export AWS_SHARED_CREDENTIALS_FILE=/dev/null

function as_parent {
    AWS_ACCESS_KEY_ID=parent-identity \
    AWS_SECRET_ACCESS_KEY=parent-credential \
    AWS_SESSION_TOKEN= \
        aws --endpoint-url "${ENDPOINT}" "$@"
}

function as_session {
    AWS_ACCESS_KEY_ID="${SESSION_KEY}" \
    AWS_SECRET_ACCESS_KEY="${SESSION_SECRET}" \
    AWS_SESSION_TOKEN="${SESSION_TOKEN}" \
        aws --endpoint-url "${ENDPOINT}" "$@"
}

failures=0
function expect_ok {
    local what=$1; shift
    if "$@" > "${WORK}/out" 2>&1; then
        echo "ok      ${what}"
    else
        echo "FAILED  ${what}: expected success"; cat "${WORK}/out"
        failures=$((failures + 1))
    fi
}
function expect_denied {
    local what=$1; local code=$2; shift 2
    if "$@" > "${WORK}/out" 2>&1; then
        echo "FAILED  ${what}: expected ${code}, succeeded"
        failures=$((failures + 1))
    elif grep -q "${code}" "${WORK}/out"; then
        echo "ok      ${what} (${code})"
    else
        echo "FAILED  ${what}: expected ${code}"; cat "${WORK}/out"
        failures=$((failures + 1))
    fi
}

# The HTTP status of a GET, for the presigned URLs no aws command fetches.
function http_status {
    curl --silent --output /dev/null --write-out '%{http_code}' "$1"
}
function expect_status {
    local what=$1; local want=$2; local url=$3
    local got
    got=$(http_status "${url}")
    if [ "${got}" = "${want}" ]; then
        echo "ok      ${what} (${got})"
    else
        echo "FAILED  ${what}: expected ${want}, got ${got}"
        failures=$((failures + 1))
    fi
}

echo data > "${WORK}/file"
as_parent s3 mb s3://data > /dev/null
as_parent s3 cp "${WORK}/file" s3://data/users/bob/secret > /dev/null

POLICY='{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],
   "Resource":"arn:aws:s3:::data/users/alice/*"},
  {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::data",
   "Condition":{"StringLike":{"s3:prefix":"users/alice/*"}}}]}'

# Mint in its own command so that a failure stops the script with the
# CLI's error rather than an empty read.
if ! as_parent sts get-federation-token --name alice-job \
        --duration-seconds 3600 --policy "${POLICY}" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text > "${WORK}/creds" 2> "${WORK}/mint-error"; then
    echo "FAILED  get-federation-token"; cat "${WORK}/mint-error"
    exit 1
fi
read -r SESSION_KEY SESSION_SECRET SESSION_TOKEN < "${WORK}/creds"
echo "minted  ${SESSION_KEY}"

expect_ok "put inside prefix" \
    as_session s3 cp "${WORK}/file" s3://data/users/alice/a.txt
expect_ok "get inside prefix" \
    as_session s3 cp s3://data/users/alice/a.txt "${WORK}/back"
expect_ok "list inside prefix" \
    as_session s3api list-objects-v2 --bucket data --prefix users/alice/
expect_denied "put outside prefix" AccessDenied \
    as_session s3 cp "${WORK}/file" s3://data/users/bob/planted
expect_denied "get outside prefix" AccessDenied \
    as_session s3api get-object --bucket data --key users/bob/secret \
    "${WORK}/stolen"
expect_denied "list whole bucket" AccessDenied \
    as_session s3api list-objects-v2 --bucket data
expect_denied "delete not granted" AccessDenied \
    as_session s3api delete-object --bucket data --key users/alice/a.txt
expect_denied "list buckets not granted" AccessDenied \
    as_session s3api list-buckets
expect_denied "session cannot mint more" AccessDenied \
    as_session sts get-federation-token --name again
expect_denied "unsupported policy element" MalformedPolicyDocument \
    as_parent sts get-federation-token --name bad \
    --policy '{"Statement":{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}}'

URL=$(as_session s3 presign s3://data/users/alice/a.txt --expires-in 300)
expect_status "presigned get inside prefix" 200 "${URL}"
URL=$(as_session s3 presign s3://data/users/bob/secret --expires-in 300)
expect_status "presigned get outside prefix" 403 "${URL}"
# AWS CLI v1 presigns with SigV2 unless told otherwise, which temporary
# credentials do not accept; v2 always uses SigV4, so only check v1.
URL=$(AWS_CONFIG_FILE=/dev/null as_session s3 presign \
    s3://data/users/alice/a.txt --expires-in 300)
case "${URL}" in
*AWSAccessKeyId=*)
    expect_status "SigV2 presigned url refused" 403 "${URL}" ;;
esac

if [ "${failures}" -ne 0 ]; then
    echo "${failures} check(s) failed"
    exit 1
fi
echo "all checks passed"

# Temporary credentials (STS)

Status: experimental

S3Proxy can answer the STS `GetFederationToken` action, letting a configured
identity mint short-lived credentials that are scoped down by a session
policy: limited to some buckets, some key prefixes, some operations.  Clients
use the stock AWS SDKs and CLI pointed at S3Proxy's endpoint; nothing
client-side is S3Proxy-specific.

## Configuration

```
s3proxy.authorization=aws-v4
s3proxy.identity=local-identity
# use a long random secret: see Security below
s3proxy.credential=<at least 32 random characters>
s3proxy.sts.enabled=true
# optional: the longest session issued, in seconds (900 to 129600)
s3proxy.sts.max-duration=3600
```

STS requires `aws-v4` or `aws-v2-or-v4` authorization.  Temporary
credentials sign with AWS Signature Version 4 only.

## Minting credentials

```
aws --endpoint-url http://127.0.0.1:8080 sts get-federation-token \
    --name alice-job --duration-seconds 3600 \
    --policy '{"Version": "2012-10-17", "Statement": [
      {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
       "Resource": "arn:aws:s3:::data/users/alice/*"},
      {"Effect": "Allow", "Action": "s3:ListBucket",
       "Resource": "arn:aws:s3:::data",
       "Condition": {"StringLike": {"s3:prefix": "users/alice/*"}}}]}'
```

The response carries an `AccessKeyId`, `SecretAccessKey` and `SessionToken`
which any AWS client accepts as session credentials.  A session minted
without a policy may do nothing.  Session credentials cannot mint further
sessions.

## Session policies

Policies use a subset of the IAM policy language:

* `Effect`: `Allow` or `Deny`; an explicit Deny wins, and anything no
  statement allows is denied
* `Action`: `s3:` actions, or `*`, with `*` and `?` wildcards
* `Resource`: `arn:aws:s3:::bucket` and `arn:aws:s3:::bucket/key` ARNs, or
  `*`, with wildcards
* `Condition`: `StringEquals` and `StringLike` on `s3:prefix` and
  `s3:delimiter`, which scope listings

Anything else -- `NotAction`, `NotResource`, `Principal`, other condition
operators or keys, policy variables -- is refused with
`MalformedPolicyDocument` rather than ignored.  Policies are limited to 2048
bytes of UTF-8, so that the token carrying one fits in a request header.

Each S3 operation requires the IAM action AWS documents for it, e.g.
`HeadObject` requires `s3:GetObject`, multipart uploads require
`s3:PutObject`, a copy requires `s3:GetObject` on its source and
`s3:PutObject` on its destination, `DeleteObjects` requires `s3:DeleteObject`
on every key, `GetObjectAttributes` requires `s3:GetObject` as well, and
writing with a non-private `x-amz-acl` also requires `s3:PutObjectAcl`.
Operations naming a `versionId` require the `*Version` actions, e.g.
`s3:GetObjectVersion`, `s3:DeleteObjectVersion`.

Keys with empty, `.` or `..` path segments (e.g. `home/alice/../bob/x`, or
a key starting with `/`) are refused for temporary credentials: a filesystem
backend resolves them to a different object than the one the policy
matched.  A trailing `/`, as directory markers have, is allowed.

## Design

S3Proxy stores nothing about the sessions it issues.  The minting
identity's secret is expanded with HKDF into two keys.  The session token is
an AES-256-GCM encryption of the temporary access key id, expiry, name and
policy under one; the temporary secret access key is an HMAC of the access
key id under the other.  Consequently:

* any S3Proxy configured with the same identity and secret accepts the
  token, so replicas need no shared state
* changing or removing the identity's secret revokes every session it
  minted
* an individual session cannot be revoked before it expires

## Security

Use a strong parent secret: at least 32 random characters, as an AWS secret
access key has.  Temporary credentials are derived from it, so whoever holds
them can test guesses at the parent secret offline, and a correct guess
grants everything the parent may do, including minting further sessions.  A
short or memorable secret such as the sample `local-credential` would fall
quickly.

The session token is redacted from S3Proxy's header trace log.

## Limitations

* Only `GetFederationToken` is implemented; `AssumeRole`,
  `GetSessionToken` and `GetCallerIdentity` are not.
* Browser POST uploads (POST policy forms) do not accept session
  credentials.
* Temporary credentials do not work with AWS Signature Version 2.
* Policies match keys case-sensitively, as S3 does.  A filesystem backend
  on a case-insensitive filesystem (e.g. macOS's default APFS) does not:
  there `home/alice/SECRET/x` opens the same file as `home/alice/secret/x`,
  so do not rely on a Deny, or on prefixes differing only in case, to
  separate them.
* With `s3proxy.virtual-host` set, STS requests must carry the virtual host
  itself as their Host; any other host name is read as a bucket.
* With `s3proxy.service-path` set, the AWS SDKs POST STS requests to the
  service path without a trailing slash, which S3Proxy redirects; they
  cannot mint credentials through it.

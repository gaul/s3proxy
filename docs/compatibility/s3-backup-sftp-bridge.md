# S3 Backup to SFTP Bridge

Status: embedded SFTP profile validated

## Problem

An application backup/restore workflow currently writes backups through an
S3-compatible storage interface. The backup target is reachable over SFTP. The
bridge lets an S3 backup client keep using its S3 settings while S3Proxy
translates those S3 operations to the SFTP server.

Target deployment shape:

```
S3 backup client -> S3Proxy endpoint -> SFTP backend -> SFTP root
```

## S3 Client Configuration Shape

An S3 backup client configuration commonly supports:

- `accessKey`
- `secretKey`
- `bucketName`
- `serviceEndpoint`
- `disableSslValidation`
- `certificate`
- `writeOnly`
- `disableChecksumValidation`

For this bridge, `serviceEndpoint` should point at S3Proxy and `bucketName`
should be the S3Proxy bucket that maps to the SFTP remote directory.
S3Proxy authentication credentials should remain distinct from backend SFTP
credentials.

Path formula:

`remote_path = jclouds.sftp.basedir / bucketName / objectKey`

So `bucketName` is not ignored: it is the first folder level under the SFTP
base directory for all backup objects.

## Required S3 Operations

The S3 backup path uses the following S3 operations through AWS SDK v2:

- `putObject` for backup payload objects and `entry.txt` metadata objects;
- `headObject` before reading a payload object;
- `getObject` for backup payload objects and `entry.txt` metadata objects;
- `listObjectsV2` with a prefix such as `backups/snapshot/`;
- `deleteObject` for payload objects and metadata objects.

The AWS SDK v2 client uses path-style access and a configurable endpoint
override. Region parsing falls back to `us-east-1` for S3-compatible endpoints.

## Key Layout

An S3 backup workflow stores entries under a configured prefix, commonly:

```
backups/snapshot/<snapshot-id>/snapshot.zip
backups/snapshot/<snapshot-id>/entry.txt
backups/app/<backup-id>/db_dump.zip
backups/app/<backup-id>/entry.txt
```

The SFTP backend must preserve this hierarchy under the configured remote base
directory.

## First Acceptance Test

`S3BackupSftpBridgeTest` starts S3Proxy with the SFTP backend pointed at an
embedded SFTP server, then runs the equivalent of:

1. Create bucket.
2. Upload `backups/snapshot/100/snapshot.zip`.
3. Upload `backups/snapshot/100/entry.txt`.
4. Upload `backups/app/1000/db_dump.zip`.
5. Upload `backups/app/1000/entry.txt`.
6. `HEAD` the payload objects.
7. `GET` the payload and metadata objects.
8. List `backups/snapshot/` and `backups/app/`.
9. Delete the payload and metadata objects.

The test includes multi-megabyte payload objects through AWS SDK v2's async S3
client with path-style access and a custom endpoint. The SDK completed the
current payloads as single-part uploads; multipart remains a later compatibility
lane for larger payload thresholds.

## Operational Notes

- S3Proxy should be deployed near the S3 backup client or near the SFTP server,
  depending on network policy and latency.
- TLS for S3-client-to-S3Proxy should be enabled for SFTP target deployment unless
  traffic is constrained to a trusted local network.
- SFTP host key verification and credential handling must be explicit before
  production use.
- If the SFTP server grants write-only SFTP semantics, restore and list behavior
  will not work. Restore requires reads and listing.

## Success Boundary

This profile is green when the S3 backup operation set works end-to-end through
S3Proxy to embedded SFTP and then to an external SFTP server. Full S3 API
compatibility is useful later, but it is not the first success boundary.

# SFTP Backend

Status: S3 backup profile validated

The SFTP backend will expose an SFTP server as an S3Proxy storage backend behind
the jclouds `BlobStore` interface. The S3 protocol layer should remain
provider-neutral.

The initial validation target is the S3 backup to SFTP bridge described in
`docs/compatibility/s3-backup-sftp-bridge.md`.

## Implementation Status

The first provider spike exists under `org.gaul.s3proxy.sftp`:

- `SftpBlobStoreProviderMetadata`
- `SftpBlobStoreApiMetadata`
- `SftpBlobStoreContextModule`
- `SftpBlobStore`

The provider reuses the existing NIO.2 blobstore implementation over Apache MINA
SSHD's SFTP filesystem provider. This keeps the first implementation small and
preserves the existing BlobStore behavior surface where the remote filesystem
supports it.

## Planned Configuration

Example shape:

```
s3proxy.authorization=aws-v2-or-v4
s3proxy.endpoint=http://127.0.0.1:8080
s3proxy.identity=local-identity
s3proxy.credential=local-credential

jclouds.provider=sftp
jclouds.endpoint=sftp://127.0.0.1:2222/
jclouds.identity=sftp-user
jclouds.credential=sftp-password
jclouds.sftp.basedir=/upload-root
```

The final implementation may add key-file authentication, host-key pinning, and
connection timeout properties. These must be reflected here and in
`src/test/resources/s3proxy-sftp.conf`.

## Storage Mapping

- S3 buckets map to first-level directories below `jclouds.sftp.basedir`.
- Object keys map to files below the bucket directory.
- Keys ending in `/` are directory marker requests.
- All path resolution must normalize and reject traversal outside the configured
  base directory.

Effective path mapping is:

`<jclouds.sftp.basedir>/<bucket>/<object-key>`

Example:

- `jclouds.sftp.basedir=/data/backups`
- S3 bucket name: `example-bucket`
- Object key: `backups/app/1000/db_dump.zip`

Stored file path:

`/data/backups/example-bucket/backups/app/1000/db_dump.zip`

## Metadata Contract

The existing NIO.2 backend stores content metadata and user metadata in user
extended attributes. SFTP servers generally do not provide portable user xattrs.

The first milestone uses reduced metadata fidelity:

- Object bytes are stored as regular SFTP files.
- Object size and last-modified come from SFTP file attributes.
- Content type is inferred when persisted content-type metadata is unavailable.
- ETags are generated during upload, but portable persistence across reconnects
  is not guaranteed without sidecar metadata.
- S3 user metadata is not portable over SFTP and is not part of the S3 backup
  acceptance profile.

The shared NIO.2 backend now treats unsupported user xattrs as optional. That is
required for Apache MINA's SFTP filesystem and is also safer for other
filesystems that do not expose `UserDefinedFileAttributeView`.

## Validation Lanes

- Fixture lane: provider construction, config parsing, and path-safety tests.
- Embedded lane: run tests against an embedded Apache MINA SSHD SFTP server.
- S3 backup lane: prove the specific S3 operations used by an S3 backup client
  before broad S3 compatibility.
- S3 lane: run `AwsSdkTest` and `run-s3-tests.sh` with
  `s3proxy-sftp.conf`.
- External lane: optional validation against a real SFTP host with credentials
  supplied outside git.

## Non-Goals

- SFTP-specific S3 protocol extensions.
- Shell access or remote command execution.
- Cross-user remote filesystem administration.
- Claiming full S3 metadata parity until the selected metadata strategy proves
  it with tests.

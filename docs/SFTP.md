# SFTP

Status: experimental

The SFTP backend exposes an SFTP server as an S3Proxy storage backend through
S3Proxy's `BlobStore` interface. It reuses the existing NIO.2 blobstore
implementation over Apache MINA SSHD's SFTP filesystem provider.

## Security

The SFTP backend requires a pinned SFTP server host-key fingerprint. Set
`s3proxy.sftp.host-key` to the expected fingerprint, for example
`SHA256:...`. S3Proxy rejects the SFTP connection if the server presents a
different host key.

Keep S3Proxy client credentials separate from SFTP credentials. S3 clients
authenticate to S3Proxy with `s3proxy.identity` and `s3proxy.credential`; S3Proxy
authenticates to the SFTP server with `jclouds.identity` and
`jclouds.credential`.

## Configuration

Example:

```
s3proxy.authorization=aws-v2-or-v4
s3proxy.endpoint=http://127.0.0.1:8080
s3proxy.identity=local-identity
s3proxy.credential=local-credential

jclouds.provider=sftp
jclouds.endpoint=sftp://127.0.0.1:2222/
jclouds.identity=sftp-user
jclouds.credential=sftp-password
s3proxy.sftp.basedir=/s3proxy
s3proxy.sftp.host-key=SHA256:...
```

If `jclouds.endpoint` omits a port, the backend uses SFTP port 22. The default
`s3proxy.sftp.basedir` is `/s3proxy`.

You can usually get an OpenSSH-format SHA256 host-key fingerprint with:

```
ssh-keyscan -p 2222 127.0.0.1 | ssh-keygen -lf -
```

## Storage Mapping

S3 buckets are first-level directories below `s3proxy.sftp.basedir`. Object keys
map to files below the bucket directory. The effective path mapping is:

```
<s3proxy.sftp.basedir>/<bucket>/<object-key>
```

Example:

```
s3proxy.sftp.basedir=/data/backups
bucket=example-bucket
object-key=backups/app/1000/db_dump.zip
```

Stored SFTP path:

```
/data/backups/example-bucket/backups/app/1000/db_dump.zip
```

The bucket name is therefore part of the SFTP path. For S3-compatible backup
clients, configure the client bucket name to the directory name you want under
`s3proxy.sftp.basedir`.

## Metadata

The NIO.2 backend stores content metadata and user metadata in user extended
attributes when the filesystem supports them. SFTP servers generally do not
provide portable user extended attributes, so the SFTP backend treats them as
optional.

Object bytes are stored as regular SFTP files. Object size and last-modified
values come from SFTP file attributes. S3 user metadata is not portable across
SFTP servers.

## Compatibility Profile

The full `AwsSdkTest` suite runs against the SFTP backend in CI.  The
`s3proxy-sftp.conf` test configuration pins the fingerprint of the checked-in
`sftp-test-host-key`, and `SftpTestServerListener` starts an embedded SFTP
server on the configured endpoint for the whole test JVM, so the lane needs no
external setup:

```
mvn test -Ds3proxy.test.conf=s3proxy-sftp.conf -Dtest=AwsSdkTest
```

The suite exercises object CRUD, listing, copy, multipart upload, ranged
reads, checksum validation during upload, and `If-None-Match: *` conditional
writes.  Tests whose observations require persisted metadata skip on sftp
(`Quirks.NO_PERSISTED_METADATA`): stored Content-Type and other content
metadata, user metadata, ETags of previously written objects, persisted
checksums, storage classes, and the conditional requests that compare against
a stored ETag.  The encrypted blobstore layer requires persisted metadata and
does not work over sftp.

Behavior against a real OpenSSH server may still differ from the embedded
Apache MINA server and should be validated before production use.

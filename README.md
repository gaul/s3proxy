# S3Proxy

[![Github All Releases](https://img.shields.io/github/downloads/gaul/s3proxy/total.svg)](https://github.com/gaul/s3proxy/releases/)
[![Docker Pulls](https://img.shields.io/docker/pulls/andrewgaul/s3proxy.svg)](https://hub.docker.com/r/andrewgaul/s3proxy/)
[![Maven Central](https://img.shields.io/maven-central/v/org.gaul/s3proxy.svg)](https://search.maven.org/#search%7Cga%7C1%7Ca%3A%22s3proxy%22)
[![Twitter Follow](https://img.shields.io/twitter/follow/S3Proxy.svg?style=social&label=Follow)](https://twitter.com/S3Proxy)

S3Proxy implements the
[S3 API](https://en.wikipedia.org/wiki/Amazon_S3#S3_API_and_competing_services)
and *proxies* requests, enabling several use cases:

* translation from S3 to Backblaze B2, EMC Atmos, Google Cloud, Microsoft Azure, and OpenStack Swift
* testing without Amazon by using the local filesystem
* extension via middlewares
* embedding into Java applications

## Usage with Docker

[Docker Hub](https://hub.docker.com/r/andrewgaul/s3proxy/) hosts a Docker image
and has instructions on how to run it.

## Usage with Kubernetes

[Reference manifests](examples/kubernetes/) show how to wire the Docker image
into Kubernetes, including health probes, graceful shutdown, and Secret-based
credentials.  Helm users may prefer the third-party
[s3proxy-chart](https://github.com/comet-ml/s3proxy-chart).

## Usage without Docker

Users can [download releases](https://github.com/gaul/s3proxy/releases)
from GitHub.  Developers can build the project by running `mvn package` which
produces a binary at `target/s3proxy`.  S3Proxy requires Java 17 or newer to
run.

Configure S3Proxy via a properties file.  An example using the local
file system as the storage backend with anonymous access:

```
s3proxy.authorization=none
s3proxy.endpoint=http://127.0.0.1:8080
jclouds.provider=filesystem
jclouds.filesystem.basedir=/tmp/s3proxy
```

First create the filesystem basedir:

```
mkdir /tmp/s3proxy
```

Next run S3Proxy.  Linux and Mac OS X users can run the executable jar:

```
chmod +x s3proxy
s3proxy --properties s3proxy.conf
```

Windows users must explicitly invoke java:

```
java -jar s3proxy --properties s3proxy.conf
```

Finally test by creating a bucket then listing all the buckets:

```
$ curl --request PUT http://localhost:8080/testbucket

$ curl http://localhost:8080/
<?xml version="1.0" ?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID><DisplayName>CustomersName@amazon.com</DisplayName></Owner><Buckets><Bucket><Name>testbucket</Name><CreationDate>2015-08-05T22:16:24.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>
```

## Usage with Java

Maven Central hosts S3Proxy artifacts and the wiki has
[instructions on Java use](https://github.com/gaul/s3proxy/wiki/Using-S3Proxy-in-Java-projects).

## Supported storage backends

* atmos
* aws-s3 (Amazon-only, alias for aws-s3-sdk)
* aws-s3-sdk (S3-compatible backends via AWS SDK, recommended)
* aws-s3-jclouds (Amazon-only via jclouds, deprecated)
* azureblob (alias for azureblob-sdk)
* azureblob-sdk (recommended)
* azureblob-jclouds (Azure Blob via jclouds, deprecated)
* b2
* filesystem (on-disk storage, alias for filesystem-nio2)
* filesystem-nio2 (on-disk storage, recommended)
* filesystem-jclouds (on-disk storage via jclouds, deprecated)
* google-cloud-storage (alias for google-cloud-storage-sdk)
* google-cloud-storage-sdk (recommended)
* google-cloud-storage-jclouds (Google Cloud Storage via jclouds, deprecated)
* openstack-swift (OpenStack Swift via jclouds)
* openstack-swift-sdk (OpenStack Swift via openstack4j, Keystone v3 only)
* rackspace-cloudfiles-uk and rackspace-cloudfiles-us
* s3 (non-Amazon, alias for aws-s3-sdk)
* s3-jclouds (non-Amazon S3 via jclouds, deprecated)
* sftp (SFTP storage via Apache MINA SSHD)
* transient (in-memory storage, alias for transient-nio2)
* transient-nio2 (in-memory storage, recommended)
* transient-jclouds (in-memory storage via jclouds, deprecated)

See the wiki for [examples of configurations](https://github.com/gaul/s3proxy/wiki/Storage-backend-examples).

## Assigning buckets to backends

S3Proxy can be configured to assign buckets to different backends with the same
credentials. The configuration in the properties file is as follows:
```
s3proxy.bucket-locator.1=bucket
s3proxy.bucket-locator.2=another-bucket
```

In addition to the explicit names, [glob syntax](https://docs.oracle.com/javase/tutorial/essential/io/fileOps.html#glob) can be used to configure many
buckets for a given backend.

A bucket (or a glob) cannot be assigned to multiple backends.

## Middlewares

S3Proxy can modify its behavior based on middlewares:

* [bucket aliasing](https://github.com/gaul/s3proxy/wiki/Middleware-alias-blobstore)
* [bucket prefix scoping](https://github.com/gaul/s3proxy/wiki/Middleware-prefix-blobstore)
* [bucket locator](https://github.com/gaul/s3proxy/wiki/Middleware-bucket-locator)
* [eventual consistency modeling](https://github.com/gaul/s3proxy/wiki/Middleware---eventual-consistency)
* [large object mocking](https://github.com/gaul/s3proxy/wiki/Middleware-large-object-mocking)
* [latency](https://github.com/gaul/s3proxy/wiki/Middleware-latency)
* [read-only](https://github.com/gaul/s3proxy/wiki/Middleware-read-only)
* [regex rename blobs](https://github.com/gaul/s3proxy/wiki/Middleware-regex)
* [sharded backend containers](https://github.com/gaul/s3proxy/wiki/Middleware-sharded-backend)
* [storage class override](https://github.com/gaul/s3proxy/wiki/Middleware-storage-class-override)
* [user metadata replacer](https://github.com/gaul/s3proxy/wiki/Middleware-user-metadata-replacer)
* [no cache override](https://github.com/gaul/s3proxy/wiki/Middleware-no-cache)

## SSL Support

S3Proxy can listen on HTTPS by setting the `secure-endpoint` and [configuring a keystore](http://wiki.eclipse.org/Jetty/Howto/Configure_SSL#Generating_Keys_and_Certificates_with_JDK_keytool). You can read more about how configure S3Proxy for SSL Support in [the dedicated wiki page](https://github.com/gaul/s3proxy/wiki/SSL-support) with Docker, Kubernetes or simply Java.

## Limitations

S3Proxy has broad compatibility with the S3 API, however, it does not support:

* ACLs other than private and public-read, including the `x-amz-grant-*` headers and any grant naming a specific grantee
* BitTorrent hosting
* bucket inventory, analytics, and metrics configuration
* bucket lifecycle configuration
* bucket logging
* bucket notification configuration
* bucket policies
* bucket policy status
* bucket replication
* conditional delete using If-Match, `x-amz-if-match-size` or `x-amz-if-match-last-modified-time`
* [CORS bucket operations](https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html#how-do-i-enable-cors) like getting or setting the CORS configuration for a bucket. S3Proxy only supports a static configuration (see below).
* hosting static websites
* object lock, including legal hold and retention
* object ownership controls
* object server-side encryption
* object tagging
* object versioning, see [#74](https://github.com/gaul/s3proxy/issues/74)
* paginating ListParts with `part-number-marker`
* public access block
* reading a single part of a multipart object with `partNumber`, unless the object has only one part
* requester pays buckets
* restoring archived objects
* [select object content](https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectSELECTContent.html)
* transfer acceleration
* `x-amz-expected-bucket-owner`

S3Proxy emulates the following operations:

* multi-part upload on the `filesystem-nio2` and `transient-nio2` backends, which store a stub object to carry the metadata
* object and bucket owners, which are always the same synthetic user

Some limitations depend on the storage backend:

| limitation | backends |
| --- | --- |
| no per-object ACLs, including public-read | `azureblob-sdk`, `openstack-swift-sdk` |
| ETag is not the object MD5 | `azureblob-sdk`, `google-cloud-storage-sdk` |
| `Cache-Control` not preserved | `google-cloud-storage-sdk`, `openstack-swift-sdk` |
| `Content-Encoding` not preserved | `google-cloud-storage-sdk` |
| `Content-Language` not preserved | `openstack-swift-sdk` |
| `Expires` not preserved | `azureblob-sdk` |
| `max-keys=0` not honored | `azureblob-sdk` |
| `UploadPartCopy` streams the data through S3Proxy instead of copying it on the backend | `filesystem-nio2`, `transient-nio2`, `openstack-swift-sdk`, `sftp` |
| conditional PUT refuses `If-Match`, honoring only `If-None-Match: *` | `openstack-swift-sdk` |

Two backends copy a part on the server but fall back to streaming it through
S3Proxy in one case each: `google-cloud-storage-sdk` for a range covering less
than the whole object, which GCS cannot copy server-side, and `azureblob-sdk`
against an endpoint that refuses Put Block From URL, which Azurite does.

Azure mints ETags like `0x8DD3F4A5F0B2C1E`, which S3 SDKs decode as hex and
abort the request when they cannot -- the AWS SDK for .NET raises
`ArgumentOutOfRangeException (Parameter 'hex')` and the one for Java reports
`Input is expected to be encoded in multiple of 2 bytes`.  `azureblob-sdk`
therefore reports it under the `-1` suffix S3 gives an object assembled from
parts, which every client already treats as a value not to verify, and takes
the suffix off again when a conditional request names one.  The ETag remains
opaque either way: it is not the object's MD5 and nothing can check the
object against it.  Set `s3proxy.azureblob.etag=native` to report the bare
Azure ETag, as releases before 4.0.0 did.

`aws-s3-sdk`, `azureblob-sdk` and `google-cloud-storage-sdk` perform a
conditional PUT on the backend.  The nio2 backends resolve `If-None-Match` as
they write and emulate `If-Match` within a single S3Proxy process, so it does
not hold against another writer.  Where a backend cannot do either, a
conditional PUT is refused rather than emulated, since emulating it would mean
a read followed by a write -- which answers correctly only when nothing else is
writing that key, and a conditional PUT is asked for precisely because
something might be.  Set `s3proxy.aws-s3.conditional-writes=emulated` for an
S3-compatible endpoint that does not implement conditional writes itself.

S3Proxy has basic CORS preflight and actual request/response handling. It can be configured within the properties
file (and corresponding ENV variables for Docker):

```
s3proxy.cors-allow-origins=https://example\.com https://.+\.example\.com https://example\.cloud
s3proxy.cors-allow-methods=GET PUT
s3proxy.cors-allow-headers=Accept Content-Type
s3proxy.cors-allow-credential=true
```

CORS cannot be configured per bucket. `s3proxy.cors-allow-all=true` will accept any origin and header.
Actual CORS requests are supported for GET, PUT, POST, HEAD and DELETE methods.
Cross-origin sharing is opt-in: a proxy with no CORS configuration, including
one built through `S3Proxy.Builder` without `corsRules`, shares nothing.
Responses that depend on the request `Origin` carry `Vary: Origin` so that
shared caches do not serve one origin's response to another.

The wiki collects
[compatibility notes](https://github.com/gaul/s3proxy/wiki/Storage-backend-compatibility)
for specific storage backends.

## Support

* [GitHub issues](https://github.com/gaul/s3proxy/issues)
* [Stack Overflow](https://stackoverflow.com/questions/tagged/s3proxy)
* [commercial support](mailto:andrew@gaul.org)

## References

* [Apache jclouds](https://jclouds.apache.org/) provides storage backend support for S3Proxy
* [Ceph s3-tests](https://github.com/ceph/s3-tests) help maintain and improve compatibility with the S3 API
* [fake-s3](https://github.com/jubos/fake-s3), [gofakes3](https://github.com/johannesboyne/gofakes3), [minio](https://github.com/minio/minio), [S3 ninja](https://github.com/scireum/s3ninja), and [s3rver](https://github.com/jamhall/s3rver) provide functionality similar to S3Proxy when using the filesystem backend
* [GlacierProxy](https://github.com/bouncestorage/glacier-proxy) and [SwiftProxy](https://github.com/bouncestorage/swiftproxy) provide similar functionality for the Amazon Glacier and OpenStack Swift APIs
* [s3mock](https://github.com/adobe/S3Mock) - Adobe's s3 mock implementation
* [s3proxy-chart](https://github.com/comet-ml/s3proxy-chart) - Helm chart for deploying S3Proxy
* [sbt-s3](https://github.com/localytics/sbt-s3) runs S3Proxy via the Scala Build Tool
* [swift3](https://github.com/openstack/swift3) provides an S3 middleware for OpenStack Swift
* [Zenko](https://www.zenko.io/) provide similar multi-cloud functionality

## License

Copyright (C) 2014-2026 Andrew Gaul

Licensed under the Apache License, Version 2.0

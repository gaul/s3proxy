# S3Proxy

[![Github All Releases](https://img.shields.io/github/downloads/gaul/s3proxy/total.svg)](https://github.com/gaul/s3proxy/releases/)
[![Docker Pulls](https://img.shields.io/docker/pulls/andrewgaul/s3proxy.svg)](https://hub.docker.com/r/andrewgaul/s3proxy/)
[![Maven Central](https://img.shields.io/maven-central/v/org.gaul/s3proxy.svg)](https://search.maven.org/#search%7Cga%7C1%7Ca%3A%22s3proxy%22)

S3Proxy implements the
[S3 API](https://en.wikipedia.org/wiki/Amazon_S3#S3_API_and_competing_services)
and *proxies* requests, enabling several use cases:

* translation from S3 to Google Cloud, Microsoft Azure, OpenStack Swift, and SFTP
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
file system as the storage backend:

```
s3proxy.authorization=aws-v4
s3proxy.identity=local-identity
s3proxy.credential=local-credential
s3proxy.endpoint=http://127.0.0.1:8080
jclouds.provider=filesystem
jclouds.filesystem.basedir=/tmp/s3proxy
```

Clients sign their requests with `s3proxy.identity` and `s3proxy.credential`
as the access key and secret key.  Settings for the storage backend start
with `jclouds.`, a prefix kept from when S3Proxy was built on Apache jclouds.

First create the filesystem basedir:

```
mkdir /tmp/s3proxy
```

Next run S3Proxy.  Linux and macOS users can run the executable jar:

```
chmod +x s3proxy
./s3proxy --properties s3proxy.conf
```

Windows users must explicitly invoke java:

```
java -jar s3proxy --properties s3proxy.conf
```

Finally test by creating a bucket then listing all the buckets:

```
$ curl --aws-sigv4 aws:amz:us-east-1:s3 --user local-identity:local-credential \
    --request PUT http://localhost:8080/testbucket

$ curl --aws-sigv4 aws:amz:us-east-1:s3 --user local-identity:local-credential \
    http://localhost:8080/
<?xml version='1.0' encoding='UTF-8'?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID><DisplayName>CustomersName@amazon.com</DisplayName></Owner><Buckets><Bucket><Name>testbucket</Name><CreationDate>2015-08-05T22:16:24.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>
```

## Usage with Java

Maven Central hosts S3Proxy artifacts and the wiki has
[instructions on Java use](https://github.com/gaul/s3proxy/wiki/Using-S3Proxy-in-Java-projects).

## Supported storage backends

* aws-s3
* azureblob
* filesystem (on-disk storage)
* google-cloud-storage
* openstack-swift (Keystone v3 only)
* sftp (SFTP storage via Apache MINA SSHD)
* transient (in-memory storage)

See the wiki for [examples of configurations](https://github.com/gaul/s3proxy/wiki/Storage-backend-examples).

## Backend credentials

`jclouds.identity` and `jclouds.credential` name the enduring half of a backend
credential.  Credentials that expire carry a third part, which
`jclouds.session-token` names: an AWS session token, an Azure shared access
signature, a Google OAuth 2.0 access token, or a Keystone token.

```
jclouds.provider=aws-s3
jclouds.identity=ASIAIOSFODNN7EXAMPLE
jclouds.credential=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
jclouds.session-token=IQoJb3JpZ2luX2VjEExample
```

A token written into the properties file serves no longer than the token
itself does.  A deployment that rotates them embeds S3Proxy and hands
`BlobStores.create` a `Supplier<Credentials>` instead: a store asks it again
for every request it signs rather than keeping the first answer, so an
assumed role, a reissued signature, or a refreshed access token takes effect
without the store being rebuilt.

Naming no credentials at all defers to the chain each backend's own tools
read -- environment, profile, container, and instance role for `aws-s3`,
`DefaultAzureCredential` for `azureblob`, and application default credentials
for `google-cloud-storage` -- every one of which renews what it finds.

`azureblob` reads its endpoint from `jclouds.endpoint`.  Left unset, it uses
`https://ACCOUNT.blob.core.windows.net` for the storage account that
`jclouds.identity` names, and refuses to start when the identity names none.

`s3proxy.azureblob.auth` says how `azureblob` authenticates: `sas`, `key`,
`default` for `DefaultAzureCredential`, or `bearer` for a Microsoft Entra
access token the application supplies in `jclouds.session-token`.  When it is
not set, the store uses `sas` if there is a session token, `key` if there are
an identity and a credential, and `default` otherwise.  The wiki covers
[Azure authentication](https://github.com/gaul/s3proxy/wiki/Azure-authentication)
in more depth, including what a bearer token needs and how to move from
S3Proxy 3.x's `jclouds.azureblob.auth=azureAd`.

Three credentials are read only when the store is built, because nothing
about them expires: an Azure account key, which the client copies out when it
is created; a Google service account key, which mints and renews access
tokens of its own; and the `sftp` password, presented once when the
connection opens.  `openstack-swift` re-reads the supplier whenever the
Keystone token it holds nears its expiry.

## Backend settings

A few settings change how a backend answers:

| setting | effect |
| --- | --- |
| `s3proxy.aws-s3.conditional-writes=emulated` | emulate conditional writes for an S3-compatible endpoint that does not implement them |
| `s3proxy.azureblob.versioning=true` | turn on S3 versioning, for a storage account whose blob versioning is enabled out of band |
| `s3proxy.azureblob.etag=native` | report Azure's bare ETag, as releases before 4.0.0 did, instead of one that S3 clients accept |
| `s3proxy.google-cloud-storage.etag=native` | report GCS's bare ETag, as releases before 4.3.0 did, instead of the object's MD5 |

## Assigning buckets to backends

One S3Proxy can serve several backends, such as two Azure storage accounts or
a filesystem beside a cloud store.  Give `--properties` once per backend:

```
s3proxy --properties one.conf --properties two.conf
```

Each file is a complete configuration.  The settings that describe S3Proxy's
own listener, `s3proxy.endpoint` and `s3proxy.authorization` among them, must
be the same in every file, and S3Proxy refuses to start when they differ.  The
`jclouds.*` settings and the middlewares belong to the one backend that the
file describes.

A request reaches a backend in one of two ways:

* **By credentials.**  Files with different values of `s3proxy.identity`
  describe backends for different clients, and the access key a client signs
  with selects its backend.
* **By bucket name.**  Files that share `s3proxy.identity` and
  `s3proxy.credential` list the buckets each backend serves:

  ```
  s3proxy.bucket-locator.1=bucket
  s3proxy.bucket-locator.2=another-bucket
  ```

  The number only tells the entries apart.  An entry can be a
  [glob](https://docs.oracle.com/javase/tutorial/essential/io/fileOps.html#glob),
  such as `archive-*`.  Entries match a bucket however its name is cased.
  A bucket or glob cannot be assigned to two backends, and a bucket that no
  entry names goes to the first file given with that identity.

For example, these two files serve a writable storage account and a read-only
one to the same client:

```
# one.conf
s3proxy.endpoint=http://127.0.0.1:8080
s3proxy.authorization=aws-v4
s3proxy.identity=local-identity
s3proxy.credential=local-credential
jclouds.provider=azureblob
jclouds.identity=account1
jclouds.credential=KEY1
s3proxy.bucket-locator.1=uploads
```

```
# two.conf
s3proxy.endpoint=http://127.0.0.1:8080
s3proxy.authorization=aws-v4
s3proxy.identity=local-identity
s3proxy.credential=local-credential
jclouds.provider=azureblob
jclouds.identity=account2
jclouds.credential=KEY2
s3proxy.bucket-locator.1=archive-*
s3proxy.read-only-blobstore=true
```

Some limits apply:

* ListBuckets returns the buckets of the first file given for the client's
  identity, not those of every backend.
* CopyObject and UploadPartCopy cannot copy between backends: they answer
  `NotImplemented` unless the source and the destination bucket resolve to
  the same properties file.
* A bucket assigned to one identity's backend is refused to every other
  identity.
* When two backends hold a bucket of the same name, the
  [alias middleware](https://github.com/gaul/s3proxy/wiki/Middleware-alias-blobstore)
  gives each a distinct name.

## Middlewares

S3Proxy can modify its behavior based on middlewares:

* [bucket aliasing](https://github.com/gaul/s3proxy/wiki/Middleware-alias-blobstore)
* [bucket locator](#assigning-buckets-to-backends)
* [bucket prefix scoping](https://github.com/gaul/s3proxy/wiki/Middleware-prefix-blobstore)
* [encryption](https://github.com/gaul/s3proxy/wiki/Middleware-encryption)
* [eventual consistency modeling](https://github.com/gaul/s3proxy/wiki/Middleware---eventual-consistency)
* [large object mocking](https://github.com/gaul/s3proxy/wiki/Middleware-large-object-mocking)
* [latency](https://github.com/gaul/s3proxy/wiki/Middleware-latency)
* [no cache override](https://github.com/gaul/s3proxy/wiki/Middleware-no-cache)
* [read-only](https://github.com/gaul/s3proxy/wiki/Middleware-read-only)
* [regex rename blobs](https://github.com/gaul/s3proxy/wiki/Middleware-regex)
* [sharded backend containers](https://github.com/gaul/s3proxy/wiki/Middleware-sharded-backend)
* [storage class override](https://github.com/gaul/s3proxy/wiki/Middleware-storage-class-override)
* [user metadata replacer](https://github.com/gaul/s3proxy/wiki/Middleware-user-metadata-replacer)

## Temporary credentials

S3Proxy can issue scoped-down temporary credentials through the STS
`GetFederationToken` action; see [docs/STS.md](docs/STS.md).

## SSL Support

S3Proxy can listen on HTTPS by setting `s3proxy.secure-endpoint` and a keystore.  The [wiki](https://github.com/gaul/s3proxy/wiki/SSL-support) explains how to create the keystore and configure HTTPS with Docker, Kubernetes, or plain Java.

## Access log

Set `s3proxy.access-log=true`, or `S3PROXY_ACCESS_LOG=true` for the Docker
image, to log one line for each request once it completes:

```
127.0.0.1 "PUT /bucket/key HTTP/1.1" 200 1000 0 12 "aws-cli/2.36.0"
```

The fields are the client address, the request line, the status, the bytes of
request and response body, the milliseconds taken, and the user agent.  The
path is logged without its query string, which in a presigned URL carries the
access key and the signature.  The lines go to the logger
`org.gaul.s3proxy.access` at the info level.

With `LOG_LEVEL=trace` S3Proxy also logs the headers of each request and the
status and headers of each response.

## Metrics

S3Proxy can expose Prometheus metrics at `/metrics`: request counts and
durations and the bytes received and sent, by S3 operation, bucket, and
status.  Set `s3proxy.metrics.enabled=true`; the wiki has
[details](https://github.com/gaul/s3proxy/wiki/Metrics).

## OpenTelemetry tracing

The standalone application can export inbound S3 request traces without a
Java agent. Export is disabled by default. To send traces to an OTLP HTTP
collector, set:

```sh
OTEL_TRACES_EXPORTER=otlp
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Use environment variables for the application process or container, or the
equivalent `-Dotel.*` JVM system properties. The default service name is
`s3proxy`; override it with `OTEL_SERVICE_NAME`.

The OpenTelemetry servlet instrumentation manages HTTP server spans, incoming
W3C trace context, sampling, and errors. S3Proxy adds S3 operation names such
as `GetObject`. URL path and query attributes are redacted to empty strings;
authentication headers are not captured. The instrumentation suppresses
duplicate server spans when a Java agent has already instrumented the request.
Requests rejected by Jetty before reaching the servlet filter are not traced.

Applications embedding S3Proxy can pass their own `OpenTelemetry` instance
through `S3Proxy.builder().openTelemetry(openTelemetry)`. The caller owns its
SDK lifecycle; stopping the proxy does not close it.

Prometheus metrics and console logging are unchanged. The servlet
instrumentation also supplies standard HTTP server metrics when explicitly
enabled with `OTEL_METRICS_EXPORTER=otlp`; metrics and log export otherwise
default to `none`. Backend client spans and OTLP log capture still require
separate instrumentation, such as the Java agent.

## CORS

S3Proxy has basic CORS preflight and actual request/response handling. It can be configured within the properties
file (and corresponding ENV variables for Docker):

```
s3proxy.cors-allow-origins=https://example\.com https://.+\.example\.com https://example\.cloud
s3proxy.cors-allow-methods=GET PUT
s3proxy.cors-allow-headers=Accept Content-Type
s3proxy.cors-allow-credential=true
```

Each origin is a regular expression that must match the whole `Origin` header.
A dot matches only a dot, escaped or not, unless a quantifier follows it as in
`.+` or `.*`.  A properties file drops a single backslash, so any other escape
must be doubled there, e.g., `\\d`.

CORS cannot be configured per bucket. `s3proxy.cors-allow-all=true` will accept any origin and header.
Actual CORS requests are supported for GET, PUT, POST, HEAD and DELETE methods.
`s3proxy.cors-allow-methods` applies to actual requests as well as preflights:
a response carries CORS headers only when both the origin and the request
method are allowed.
Cross-origin sharing is opt-in: a proxy with no CORS configuration, including
one built through `S3Proxy.Builder` without `corsRules`, shares nothing.
Responses that depend on the request `Origin` carry `Vary: Origin` so that
shared caches do not serve one origin's response to another.

A web page can also point its own DNS name at a proxy that only its visitor
reaches (DNS rebinding), which makes its requests same-origin and exempt from
CORS.  A proxy with `s3proxy.authorization=none` whose endpoints are all
loopback addresses therefore answers 403 to a request whose `Host` is not a
name it goes by: an IP address, `localhost` and names under it, the hosts of
`s3proxy.endpoint` and `s3proxy.secure-endpoint`, `s3proxy.virtual-host` and
names under it, and the space-separated names in `s3proxy.allowed-hosts`:

```
s3proxy.allowed-hosts=s3.example.com storage.internal
```

Setting that property makes any other proxy check `Host` as well, e.g., one
without credentials on a private network or in a container.  List the names
that a reverse proxy in front of S3Proxy forwards, or `*` to allow every name.

## Limitations

S3Proxy has broad compatibility with the S3 API, however, it does not support:

* ACLs other than private, public-read, and, on buckets only, public-read-write, including the `x-amz-grant-*` headers and any grant naming a specific grantee
* BitTorrent hosting
* bucket inventory, analytics, and metrics configuration
* bucket lifecycle configuration
* bucket logging
* bucket notification configuration
* bucket policies
* bucket policy status
* bucket replication
* [CORS bucket operations](https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html#how-do-i-enable-cors) like getting or setting the CORS configuration for a bucket. S3Proxy only supports a static configuration, see [CORS](#cors).
* hosting static websites
* object tagging
* paginating ListParts with `part-number-marker`
* reading a single part of a multipart object with `partNumber`, unless the object has only one part
* requester pays buckets
* restoring archived objects
* [select object content](https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectSELECTContent.html)
* transfer acceleration
* `x-amz-expected-bucket-owner`

S3Proxy emulates the following operations:

* multi-part upload on the `filesystem`, `sftp`, and `transient` backends, which store a stub object to carry the metadata
* object and bucket owners, which are always the same synthetic user

Some limitations depend on the storage backend:

| limitation | backends |
| --- | --- |
| no per-object ACLs, including public-read | `azureblob`, `openstack-swift` |
| no public-read-write buckets | `azureblob`, `openstack-swift` |
| ETag is not the object MD5 | `azureblob`; `google-cloud-storage` for a composed object, such as one completed from a multipart upload |
| on a filesystem without user extended attributes, such as NFSv3: Content-Type and user metadata are not kept, and the ETag is derived from the file rather than the MD5, see [#1210](https://github.com/gaul/s3proxy/issues/1210) | `filesystem` |
| `Cache-Control` not preserved | `google-cloud-storage`, `openstack-swift` |
| `Content-Encoding` not preserved | `google-cloud-storage` |
| `Content-Language` not preserved | `openstack-swift` |
| `Expires` not preserved | `azureblob`, `google-cloud-storage` |
| no object metadata kept: Content-Type, the other content headers, user metadata, and storage class read back as defaults, and the ETag is derived from the file rather than the MD5 | `sftp` |
| `UploadPartCopy` streams the data through S3Proxy instead of copying it on the backend | `filesystem`, `transient`, `openstack-swift`, `sftp` |
| conditional PUT refuses `If-Match`, honoring only `If-None-Match: *` | `openstack-swift`, `sftp` |
| object versioning is opt-in and needs the account versioned out of band; delete markers are emulated as tagged blobs; no per-bucket suspend, see [#1137](https://github.com/gaul/s3proxy/issues/1137) | `azureblob` |
| no object ownership controls or public access block, which `aws-s3` passes through to the service | `azureblob`, `filesystem`, `google-cloud-storage`, `openstack-swift`, `sftp`, `transient` |
| no object lock, legal hold or retention; `aws-s3` passes them through to the service, which enforces them, except on a browser `POST` upload | `azureblob`, `filesystem`, `google-cloud-storage`, `openstack-swift`, `sftp`, `transient` |
| no object versioning, see [#1138](https://github.com/gaul/s3proxy/issues/1138) | `filesystem` |
| no object versioning, for want of a service analog | `openstack-swift`, `sftp` |
| no server-side encryption, see [#1134](https://github.com/gaul/s3proxy/issues/1134) | `google-cloud-storage` |
| no server-side encryption, by design or for want of a service analog | `filesystem`, `openstack-swift`, `sftp` |
| SSE-S3 only: AES256 relayed from Azure's own at-rest encryption; SSE-C ([#1135](https://github.com/gaul/s3proxy/issues/1135)) and SSE-KMS refused | `azureblob` |

The wiki explains
[how each backend behaves](https://github.com/gaul/s3proxy/wiki/Storage-backend-compatibility)
in more depth: versioning, server-side encryption, ETags, conditional writes
and deletes, and the `filesystem` backend on Windows.

## Support

* [GitHub issues](https://github.com/gaul/s3proxy/issues)
* [Stack Overflow](https://stackoverflow.com/questions/tagged/s3proxy)
* [commercial support](mailto:andrew@gaul.org)

## References

* [Ceph s3-tests](https://github.com/ceph/ceph/tree/main/src/test/rgw/s3-tests) help maintain and improve compatibility with the S3 API
* [gofakes3](https://github.com/johannesboyne/gofakes3), [minio](https://github.com/minio/minio), and [S3 ninja](https://github.com/scireum/s3ninja) provide functionality similar to S3Proxy when using the filesystem backend
* [s3mock](https://github.com/adobe/S3Mock) - Adobe's s3 mock implementation
* [s3proxy-chart](https://github.com/comet-ml/s3proxy-chart) - Helm chart for deploying S3Proxy
* [Zenko](https://www.zenko.io/) provide similar multi-cloud functionality

## License

Copyright (C) 2014-2026 Andrew Gaul

Licensed under the Apache License, Version 2.0

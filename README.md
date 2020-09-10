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

## Usage without Docker

Users can [download releases](https://github.com/gaul/s3proxy/releases)
from GitHub.  Developers can build the project by running `mvn package` which
produces a binary at `target/s3proxy`.  S3Proxy requires Java 7 to run.

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
* aws-s3 (Amazon-only)
* azureblob
* b2
* filesystem (on-disk storage)
* google-cloud-storage
* openstack-swift
* rackspace-cloudfiles-uk and rackspace-cloudfiles-us
* s3 (all implementations)
* transient (in-memory storage)

See the wiki for [examples of configurations](https://github.com/gaul/s3proxy/wiki/Storage-backend-examples).

## Middlewares

S3Proxy can modify its behavior based on middlewares:

* [eventual consistency modeling](https://github.com/gaul/s3proxy/wiki/Middleware---eventual-consistency)
* [large object mocking](https://github.com/gaul/s3proxy/wiki/Middleware-large-object-mocking)
* [read-only](https://github.com/gaul/s3proxy/wiki/Middleware-read-only)

## Limitations

S3Proxy has broad compatibility with the S3 API, however, it does not support:

* ACLs other than private and public-read
* BitTorrent hosting
* bucket logging
* bucket policies
* [CORS bucket operations](https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html#how-do-i-enable-cors) like getting or setting the CORS configuration for a bucket. S3Proxy only supports a static configuration (see below).
* hosting static websites
* object server-side encryption
* object tagging
* object versioning, see [#74](https://github.com/gaul/s3proxy/issues/74)
* POST upload policies, see [#73](https://github.com/gaul/s3proxy/issues/73)
* requester pays buckets
* [select object content](https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectSELECTContent.html)

S3Proxy emulates the following operations:

* copy multi-part objects, see [#76](https://github.com/gaul/s3proxy/issues/76)

S3Proxy has basic CORS preflight and actual request/response handling. It can be configured within the properties
file (and corresponding ENV variables for Docker):

```
s3proxy.cors-allow-origins=https://example\.com https://.+\.example\.com https://example\.cloud
s3proxy.cors-allow-methods=GET PUT
s3proxy.cors-allow-headers=Accept Content-Type
```

CORS cannot be configured per bucket. `s3proxy.cors-allow-all=true` will accept any origin and header.
Actual CORS requests are supported for GET, PUT and POST methods.

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
* [fake-s3](https://github.com/jubos/fake-s3), [gofakes3](https://github.com/johannesboyne/gofakes3), [S3 ninja](https://github.com/scireum/s3ninja), and [s3rver](https://github.com/jamhall/s3rver) provide functionality similar to S3Proxy when using the filesystem backend
* [GlacierProxy](https://github.com/bouncestorage/glacier-proxy) and [SwiftProxy](https://github.com/bouncestorage/swiftproxy) provide similar functionality for the Amazon Glacier and OpenStack Swift APIs
* [minio](https://github.com/minio/minio) and [Zenko](https://www.zenko.io/) provide similar multi-cloud functionality
* [s3mock](https://github.com/findify/s3mock) mocks the S3 API for Java/Scala projects
* [sbt-s3](https://github.com/localytics/sbt-s3) runs S3Proxy via the Scala Build Tool
* [swift3](https://github.com/openstack/swift3) provides an S3 middleware for OpenStack Swift

## License

Copyright (C) 2014-2020 Andrew Gaul

Licensed under the Apache License, Version 2.0

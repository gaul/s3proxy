S3Proxy
=======
S3Proxy allows applications using the S3 API to interface with a variety of
object stores, e.g., EMC Atmos, Microsoft Azure, OpenStack Swift.  It runs a
local HTTP server which translates S3 operations into provider-specific
operations.  S3Proxy also allows developers to test against S3 without the cost
or latency associated with using AWS by using the local file system.

Features
--------
* create, remove, and list buckets (including user-specified regions)
* put, get, delete, and list objects
* store and retrieve object metadata, including user metadata

Supported object stores:

* atmos
* aws-s3
* azureblob
* cloudfiles-uk and cloudfiles-us
* filesystem (on-disk storage)
* hpcloud-objectstorage
* s3
* swift and swift-keystone
* transient (in-memory storage)

Installation
------------
Users can
[download releases](https://github.com/andrewgaul/s3proxy/releases) from GitHub
and should `chmod +x s3proxy` afterwards.

One can also build the project by running `mvn package` which produces a binary
at `target/s3proxy`.

S3Proxy requires Java 7 to run.

Examples
--------
Linux and Mac OS users can run S3Proxy either via the executable jar or by
explicitly invoking java:

```
s3proxy --properties s3proxy.conf
java -jar s3proxy --properties s3proxy.conf
```

Windows users must explicitly invoke java.

Configuration
-------------
Users can configure S3Proxy via a properties file.  An example:

```
jclouds.provider=transient
jclouds.identity=identity
jclouds.credential=credential
# endpoint is optional for some providers
#jclouds.endpoint=http://127.0.0.1:8081
jclouds.filesystem.basedir=/tmp/blobstore

s3proxy.endpoint=http://127.0.0.1:8080
# authorization must be aws-v2 or none
s3proxy.authorization=aws-v2
s3proxy.identity=identity
s3proxy.credential=credential
```

Users can also set a variety of Java and
[jclouds properties](https://github.com/jclouds/jclouds/blob/master/core/src/main/java/org/jclouds/Constants.java).

Limitations
-----------
S3Proxy does not support:

* single-part uploads larger than 2 GB ([upstream issue](https://github.com/jclouds/jclouds/pull/426))
* multi-part uploads
* POST uploads
* bucket and object ACLs
* object metadata with filesystem provider ([upstream issue](https://github.com/jclouds/jclouds/pull/443))
* listening on HTTPS

References
----------
Apache [jclouds](http://jclouds.apache.org/) provides object store support for
S3Proxy.  Ceph [s3-tests](https://github.com/ceph/s3-tests) help maintain
and improve compatibility with the S3 API.

License
-------
Copyright (C) 2014 Andrew Gaul

Licensed under the Apache License, Version 2.0

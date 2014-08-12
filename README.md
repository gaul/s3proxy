S3Proxy
=======
S3Proxy allows applications using the S3 API to interface with a variety of
object stores, e.g., EMC Atmos, Microsoft Azure, OpenStack Swift.  It also
allows local testing against S3 without the cost or latency associated with
using AWS.

Features
--------
* create, remove, and list buckets (including user-specified regions)
* put, get, delete, and list objects
* store and retrieve object metadata, including user metadata
* authorization via AWS signature v2 (including pre-signed URLs) or anonymous access

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
Users can [download releases](https://github.com/andrewgaul/s3proxy/releases)
from GitHub.  One can also build the project by running `mvn package` which
produces a binary at `target/s3proxy`.  S3Proxy requires Java 7 to run.

Examples
--------
Linux and Mac OS users can run S3Proxy via the executable jar:

```
chmod +x s3proxy
s3proxy --properties s3proxy.conf
```

Windows users must explicitly invoke java:

```
java -jar s3proxy --properties s3proxy.conf
```

Users can configure S3Proxy via a properties file.  An example using Rackspace
CloudFiles (based on OpenStack Swift) as the backing store:

```
s3proxy.endpoint=http://127.0.0.1:8080
s3proxy.authorization=aws-v2
s3proxy.identity=local-identity
s3proxy.credential=local-credential
jclouds.provider=cloudfiles-us
jclouds.identity=remote-identity
jclouds.credential=remote-credential
```

Another example using the local file system as the backing store with anonymous
access:

```
s3proxy.authorization=none
s3proxy.endpoint=http://127.0.0.1:8080
jclouds.provider=filesystem
jclouds.identity=identity
jclouds.credential=credential
jclouds.filesystem.basedir=/tmp
```

Users can also set a variety of Java and
[jclouds properties](https://github.com/jclouds/jclouds/blob/master/core/src/main/java/org/jclouds/Constants.java).

Limitations
-----------
S3Proxy does not support:

* single-part uploads larger than 2 GB ([jclouds issue](https://issues.apache.org/jira/browse/JCLOUDS-264))
* multi-part uploads
* POST uploads
* bucket and object ACLs ([jclouds issue](https://issues.apache.org/jira/browse/JCLOUDS-660))
* object metadata with filesystem provider ([jclouds issue](https://issues.apache.org/jira/browse/JCLOUDS-658))
* object versioning
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

## Bucket Prefix Middleware

Use the prefix middleware when you want a single S3 bucket exposed by S3Proxy
to map onto a fixed prefix inside a backend bucket. This is useful when an
upstream consumer cannot specify object prefixes but your storage layout
requires them.

Enable the middleware by adding one property per bucket that should be scoped
to a prefix:

```
s3proxy.prefix-blobstore.<bucket-name>=<prefix>
```

For example, to expose `scoped-data/` objects from your backend storage as if
they were located at the top of `customer-bucket`:

```
s3proxy.prefix-blobstore.customer-bucket=scoped-data/
```

With this configuration all reads, writes, listings, and multipart uploads
issued to the `customer-bucket` bucket will transparently operate under the
`scoped-data/` prefix on the backend. Objects stored outside the configured
prefix remain untouched, and deleting the virtual bucket contents only affects
objects within the scoped prefix.

Multiple buckets can be configured and each bucket may define at most one
prefix.

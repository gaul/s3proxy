# Kubernetes examples

Reference manifests for running the S3Proxy Docker image on Kubernetes.
They are deliberately minimal and unparameterized; copy them into your
configuration management and adjust.  Helm users may prefer the third-party
[s3proxy-chart](https://github.com/comet-ml/s3proxy-chart).

Two self-contained variants:

* `cloud-backend/` proxies to a cloud blobstore (any cloud backend).
  S3Proxy is stateless in this mode: scale `replicas` freely.
* `filesystem-backend/` stores blobs on a PersistentVolumeClaim.  Run a
  single replica; the `Recreate` strategy prevents rolling updates from
  deadlocking on the ReadWriteOnce volume.

Edit the credentials in `secret.yaml`, then:

```
kubectl apply -f cloud-backend/
```

Decisions the manifests encode:

* Readiness and liveness probe `GET /healthz`, which answers without
  authentication.  During shutdown the proxy fails readiness while
  draining, so terminating pods leave the Service endpoints promptly.
* `preStop` sleeps 5 seconds to cover endpoint-propagation delay and
  `terminationGracePeriodSeconds: 40` covers it plus the proxy's
  30-second request drain.
* Credentials mount as Secret files consumed via the image's `*_FILE`
  environment variables, staying out of the pod spec and environment.
* The JVM sizes its heap from the container memory limit
  (`-XX:MaxRAMPercentage=75`), so always set a memory limit.
* The root filesystem is read-only with emptyDir volumes for `/tmp` and
  `/data`; all capabilities are dropped except `NET_BIND_SERVICE`, which
  the image needs to bind port 80 as root.  Full Pod Security Standards
  `restricted` compliance additionally needs a non-root image; see
  https://github.com/gaul/s3proxy/issues/1121.

The `*_FILE` variables and the shutdown drain require an image newer than
release 3.3.0.

# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately rather than in a public issue or
pull request. Use either of these:

* GitHub's private vulnerability reporting:
  https://github.com/gaul/s3proxy/security/advisories/new
* Email to andrew@gaul.org

Include the S3Proxy version or commit, the backend (`jclouds.provider`) and
any middlewares you configured, and a request sequence or test that
reproduces the problem.

## Supported versions

Fixes go into `master` and ship in the next release. Please check that the
problem still occurs on the latest release or on `master`.

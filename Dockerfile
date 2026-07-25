# Stage 1: create a trimmed JRE with only the modules S3Proxy needs.
# target/jdeps-modules.txt comes from `mvn package -Pjdeps`.
# Pin the build stage to the same Ubuntu release as the final image so the
# copied JRE runs against the same glibc.
FROM docker.io/library/eclipse-temurin:21-jdk-resolute AS jre-build

COPY target/jdeps-modules.txt /tmp/jdeps-modules.txt

# jdeps only sees statically-referenced modules.  Providers that the JDK
# loads reflectively via the java.security config must be listed by hand:
#   jdk.crypto.ec       - SunEC: ECDHE key agreement and ECDSA certificates
#                         for TLS connections to blobstore backends
#   jdk.crypto.cryptoki - SunPKCS11: PKCS#11 keystores, e.g. FIPS deployments
# --bind-services also links in every service provider reachable from the
# module graph (locale data, extended charsets, security providers), adding
# ~32 MB over an explicit list but guarding against providers that jdeps
# cannot see.  The CI smoke test exercises the result.
RUN jlink \
    --add-modules "$(cat /tmp/jdeps-modules.txt),jdk.crypto.ec,jdk.crypto.cryptoki" \
    --bind-services \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --compress=zip-6 \
    --output /javaruntime

# Stage 2: create the final runtime image
FROM docker.io/library/ubuntu:26.04
LABEL maintainer="Andrew Gaul <andrew@gaul.org>"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y dumb-init && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/s3proxy

# The same JAVA_HOME as the eclipse-temurin base images
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"
COPY --from=jre-build /javaruntime $JAVA_HOME

COPY \
    target/s3proxy \
    src/main/resources/run-docker-container.sh \
    /opt/s3proxy/

ENV \
    LOG_LEVEL="info" \
    S3PROXY_AUTHORIZATION="aws-v2-or-v4" \
    S3PROXY_ENDPOINT="http://0.0.0.0:80" \
    S3PROXY_IDENTITY="local-identity" \
    S3PROXY_CREDENTIAL="local-credential" \
    S3PROXY_VIRTUALHOST="" \
    S3PROXY_KEYSTORE_PATH="keystore.jks" \
    S3PROXY_KEYSTORE_PASSWORD="password" \
    S3PROXY_CORS_ALLOW_ALL="false" \
    S3PROXY_CORS_ALLOW_ORIGINS="" \
    S3PROXY_CORS_ALLOW_METHODS="" \
    S3PROXY_CORS_ALLOW_HEADERS="" \
    S3PROXY_CORS_ALLOW_CREDENTIAL="" \
    S3PROXY_V4_MAX_CHUNK_SIZE="16777216" \
    S3PROXY_IGNORE_UNKNOWN_HEADERS="false" \
    S3PROXY_ENCRYPTED_BLOBSTORE="" \
    S3PROXY_ENCRYPTED_BLOBSTORE_PASSWORD="" \
    S3PROXY_ENCRYPTED_BLOBSTORE_SALT="" \
    S3PROXY_READ_ONLY_BLOBSTORE="false" \
    S3PROXY_METRICS_ENABLED="false" \
    S3PROXY_METRICS_PORT="9090" \
    S3PROXY_METRICS_HOST="0.0.0.0" \
    JCLOUDS_PROVIDER="filesystem-nio2" \
    JCLOUDS_ENDPOINT="" \
    JCLOUDS_REGION="" \
    JCLOUDS_IDENTITY="remote-identity" \
    JCLOUDS_CREDENTIAL="remote-credential" \
    JCLOUDS_FILESYSTEM_BASEDIR="/data"

EXPOSE 80 443

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/opt/s3proxy/run-docker-container.sh"]

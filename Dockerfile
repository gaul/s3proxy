# Stage 1: create a trimmed JRE with only the modules S3Proxy needs.
# target/jdeps-modules.txt comes from `mvn package -Pjdeps`.
# Ubuntu's OpenJDK build keeps jmods, which the eclipse-temurin 25 images
# dropped, and sharing the base of the final image keeps the JRE and the
# runtime glibc identical.
FROM docker.io/library/ubuntu:26.04 AS jre-build

# binutils provides objcopy for jlink --strip-debug
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-25-jdk-headless binutils && \
    rm -rf /var/lib/apt/lists/*

COPY target/jdeps-modules.txt /tmp/jdeps-modules.txt

# jdeps only sees statically-referenced modules, so anything reached another
# way must be listed by hand:
#   jdk.crypto.cryptoki - SunPKCS11, which the java.security config loads
#     reflectively: PKCS#11 keystores, e.g. FIPS deployments
#   java.instrument - the -javaagent option, which S3PROXY_JAVA_OPTS exists
#     to pass; without the module the VM exits before main
# (SunEC lives in java.base since JDK 22.)  --bind-services also links in
# every service provider reachable from the module graph (locale data,
# extended charsets, security providers), guarding against providers that
# jdeps cannot see; --include-locales keeps only the English subset of
# jdk.localedata since the proxy formats HTTP dates with Locale.US.  The
# CI smoke test exercises the result.
RUN jlink \
    --add-modules \
        "$(cat /tmp/jdeps-modules.txt),jdk.crypto.cryptoki,java.instrument" \
    --bind-services \
    --include-locales=en \
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
    src/main/config/run-docker-container.sh \
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

# /healthz answers without authentication.  bash's /dev/tcp avoids needing
# curl in the image; the port comes from S3PROXY_ENDPOINT so overrides keep
# working.  Kubernetes ignores HEALTHCHECK; point probes at /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD bash -c 'exec 3<>"/dev/tcp/127.0.0.1/${S3PROXY_ENDPOINT##*:}" && \
        printf "GET /healthz HTTP/1.0\r\n\r\n" >&3 && \
        head -n 1 <&3 | grep -q " 200 "'

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/opt/s3proxy/run-docker-container.sh"]

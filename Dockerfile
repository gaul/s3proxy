# Stage 1: Create custom JRE with jlink
FROM docker.io/library/eclipse-temurin:21-jdk AS jre-build

WORKDIR /opt/s3proxy

# Install dumb-init in build stage
RUN apt-get update && \
    apt-get install -y dumb-init && \
    rm -rf /var/lib/apt/lists/*

# Copy the pre-computed jdeps modules list from the Maven build
COPY target/jdeps-modules.txt /tmp/modules.txt

# Display the required modules for debugging/verification
RUN cat /tmp/modules.txt

# Create a custom Java runtime with jlink
RUN jlink \
    --add-modules $(cat /tmp/modules.txt) \
    --bind-services \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --compress=2 \
    --output /javaruntime

# Copy CA certificates from the source JDK to the custom JRE
# This is essential for SSL/TLS connections to AWS S3 and other HTTPS endpoints
RUN cp $JAVA_HOME/lib/security/cacerts /javaruntime/lib/security/cacerts

# Stage 2: Create the final runtime image
FROM ubuntu:24.04
LABEL maintainer="Andrew Gaul <andrew@gaul.org>"

# update all packages in the image
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/s3proxy

# Copy dumb-init from build stage
COPY --from=jre-build /usr/bin/dumb-init /usr/bin/dumb-init

# Copy custom Java runtime from build stage
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"
COPY --from=jre-build /javaruntime $JAVA_HOME

# Copy application files
COPY \
    target/s3proxy \
    src/main/resources/run-docker-container.sh \
    /opt/s3proxy/

# Ensure the runtime script is executable inside the image
RUN chmod +x /opt/s3proxy/run-docker-container.sh

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
    JCLOUDS_REGIONS="us-east-1" \
    JCLOUDS_IDENTITY="remote-identity" \
    JCLOUDS_CREDENTIAL="remote-credential" \
    JCLOUDS_KEYSTONE_VERSION="" \
    JCLOUDS_KEYSTONE_SCOPE="" \
    JCLOUDS_KEYSTONE_PROJECT_DOMAIN_NAME="" \
    JCLOUDS_FILESYSTEM_BASEDIR="/data"

EXPOSE 80 443

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/opt/s3proxy/run-docker-container.sh"]

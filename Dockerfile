# Multistage - Builder
FROM maven:3.5.0-jdk-8-alpine as s3proxy-builder
LABEL maintainer="Andrew Gaul <andrew@gaul.org>"

WORKDIR /opt/s3proxy
COPY . /opt/s3proxy/

RUN mvn package -DskipTests

# Multistage - Image
FROM openjdk:8-jre-alpine
LABEL maintainer="Andrew Gaul <andrew@gaul.org>"

WORKDIR /opt/s3proxy

COPY \
    --from=s3proxy-builder \
    /opt/s3proxy/target/s3proxy \
    /opt/s3proxy/src/main/resources/run-docker-container.sh \
    /opt/s3proxy/

ENV \
    LOG_LEVEL="info" \
    S3PROXY_AUTHORIZATION="aws-v2-or-v4" \
    S3PROXY_IDENTITY="local-identity" \
    S3PROXY_CREDENTIAL="local-credential" \
    S3PROXY_CORS_ALLOW_ALL="false" \
    S3PROXY_CORS_ALLOW_ORIGINS="" \
    S3PROXY_CORS_ALLOW_METHODS="" \
    S3PROXY_CORS_ALLOW_HEADERS="" \
    S3PROXY_IGNORE_UNKNOWN_HEADERS="false" \
    JCLOUDS_PROVIDER="filesystem" \
    JCLOUDS_ENDPOINT="" \
    JCLOUDS_REGION="" \
    JCLOUDS_REGIONS="us-east-1" \
    JCLOUDS_IDENTITY="remote-identity" \
    JCLOUDS_CREDENTIAL="remote-credential" \
    JCLOUDS_KEYSTONE_VERSION="" \
    JCLOUDS_KEYSTONE_SCOPE="" \
    JCLOUDS_KEYSTONE_PROJECT_DOMAIN_NAME=""

EXPOSE 80
VOLUME /data

ENTRYPOINT ["/opt/s3proxy/run-docker-container.sh"]

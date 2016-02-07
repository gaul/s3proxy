FROM anapsix/alpine-java:jre7
MAINTAINER Andrew Gaul <andrew@gaul.org>

WORKDIR /opt/s3proxy
COPY target/s3proxy /opt/s3proxy/s3proxy

ENV \
    LOG_LEVEL="info" \
    S3PROXY_AUTHORIZATION="aws-v2" \
    S3PROXY_IDENTITY="local-identity" \
    S3PROXY_CREDENTIAL="local-credential" \
    JCLOUDS_PROVIDER="filesystem" \
    JCLOUDS_ENDPOINT="" \
    JCLOUDS_IDENTITY="remote-identity" \
    JCLOUDS_CREDENTIAL="remote-credential"

EXPOSE 80
VOLUME /data

ENTRYPOINT java \
    -DLOG_LEVEL=${LOG_LEVEL} \
    -Ds3proxy.endpoint=http://0.0.0.0:80 \
    -Ds3proxy.authorization=${S3PROXY_AUTHORIZATION} \
    -Ds3proxy.identity=${S3PROXY_IDENTITY} \
    -Ds3proxy.credential=${S3PROXY_CREDENTIAL} \
    -Djclouds.provider=${JCLOUDS_PROVIDER} \
    -Djclouds.identity=${JCLOUDS_IDENTITY} \
    -Djclouds.credential=${JCLOUDS_CREDENTIAL} \
    -Djclouds.filesystem.basedir=/data \
    -jar /opt/s3proxy/s3proxy \
    --properties /dev/null

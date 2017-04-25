#!/bin/sh

exec java \
    -DLOG_LEVEL=${LOG_LEVEL} \
    -Ds3proxy.endpoint=http://0.0.0.0:80 \
    -Ds3proxy.virtual-host=${S3PROXY_VIRTUALHOST} \
    -Ds3proxy.authorization=${S3PROXY_AUTHORIZATION} \
    -Ds3proxy.identity=${S3PROXY_IDENTITY} \
    -Ds3proxy.credential=${S3PROXY_CREDENTIAL} \
    -Ds3proxy.cors-allow-all=${S3PROXY_CORS_ALLOW_ALL} \
    -Djclouds.provider=${JCLOUDS_PROVIDER} \
    -Djclouds.identity=${JCLOUDS_IDENTITY} \
    -Djclouds.credential=${JCLOUDS_CREDENTIAL} \
    -Djclouds.endpoint=${JCLOUDS_ENDPOINT} \
    -Djclouds.region=${JCLOUDS_REGION} \
    -Djclouds.filesystem.basedir=/data \
    -jar /opt/s3proxy/s3proxy \
    --properties /dev/null

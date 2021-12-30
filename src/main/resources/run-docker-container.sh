#!/bin/sh

exec java \
    -DLOG_LEVEL="${LOG_LEVEL}" \
    -Ds3proxy.endpoint="${S3PROXY_ENDPOINT}" \
    -Ds3proxy.virtual-host="${S3PROXY_VIRTUALHOST}" \
    -Ds3proxy.authorization="${S3PROXY_AUTHORIZATION}" \
    -Ds3proxy.identity="${S3PROXY_IDENTITY}" \
    -Ds3proxy.credential="${S3PROXY_CREDENTIAL}" \
    -Ds3proxy.cors-allow-all="${S3PROXY_CORS_ALLOW_ALL}" \
    -Ds3proxy.cors-allow-origins="${S3PROXY_CORS_ALLOW_ORIGINS}" \
    -Ds3proxy.cors-allow-methods="${S3PROXY_CORS_ALLOW_METHODS}" \
    -Ds3proxy.cors-allow-headers="${S3PROXY_CORS_ALLOW_HEADERS}" \
    -Ds3proxy.ignore-unknown-headers="${S3PROXY_IGNORE_UNKNOWN_HEADERS}" \
    -Ds3proxy.encrypted-blobstore="${S3PROXY_ENCRYPTED_BLOBSTORE}" \
    -Ds3proxy.encrypted-blobstore-password="${S3PROXY_ENCRYPTED_BLOBSTORE_PASSWORD}" \
    -Ds3proxy.encrypted-blobstore-salt="${S3PROXY_ENCRYPTED_BLOBSTORE_SALT}" \
    -Djclouds.provider="${JCLOUDS_PROVIDER}" \
    -Djclouds.identity="${JCLOUDS_IDENTITY}" \
    -Djclouds.credential="${JCLOUDS_CREDENTIAL}" \
    -Djclouds.endpoint="${JCLOUDS_ENDPOINT}" \
    -Djclouds.region="${JCLOUDS_REGION}" \
    -Djclouds.regions="${JCLOUDS_REGIONS}" \
    -Djclouds.keystone.version="${JCLOUDS_KEYSTONE_VERSION}" \
    -Djclouds.keystone.scope="${JCLOUDS_KEYSTONE_SCOPE}" \
    -Djclouds.keystone.project-domain-name="${JCLOUDS_KEYSTONE_PROJECT_DOMAIN_NAME}" \
    -Djclouds.filesystem.basedir="/data" \
    -jar /opt/s3proxy/s3proxy \
    --properties /dev/null

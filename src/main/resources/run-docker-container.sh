#!/bin/sh

exec java \
    $S3PROXY_JAVA_OPTS \
    -DLOG_LEVEL="${LOG_LEVEL}" \
    -Ds3proxy.endpoint="${S3PROXY_ENDPOINT}" \
    -Ds3proxy.secure-endpoint="${S3PROXY_SECURE_ENDPOINT}" \
    -Ds3proxy.virtual-host="${S3PROXY_VIRTUALHOST}" \
    -Ds3proxy.keystore-path="${S3PROXY_KEYSTORE_PATH}" \
    -Ds3proxy.keystore-password="${S3PROXY_KEYSTORE_PASSWORD}" \
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
    -Ds3proxy.v4-max-non-chunked-request-size="${S3PROXY_V4_MAX_NON_CHUNKED_REQ_SIZE:-33554432}" \
    -Djclouds.provider="${JCLOUDS_PROVIDER}" \
    -Djclouds.identity="${JCLOUDS_IDENTITY}" \
    -Djclouds.credential="${JCLOUDS_CREDENTIAL}" \
    -Djclouds.endpoint="${JCLOUDS_ENDPOINT}" \
    -Djclouds.region="${JCLOUDS_REGION}" \
    -Djclouds.regions="${JCLOUDS_REGIONS}" \
    -Djclouds.keystone.version="${JCLOUDS_KEYSTONE_VERSION}" \
    -Djclouds.keystone.scope="${JCLOUDS_KEYSTONE_SCOPE}" \
    -Djclouds.keystone.project-domain-name="${JCLOUDS_KEYSTONE_PROJECT_DOMAIN_NAME}" \
    -Djclouds.filesystem.basedir="${JCLOUDS_FILESYSTEM_BASEDIR}" \
    -Djclouds.azureblob.tenantId="${JCLOUDS_AZUREBLOB_TENANTID}" \
    -Djclouds.azureblob.auth="${JCLOUDS_AZUREBLOB_AUTH}" \
    -Djclouds.azureblob.account="${JCLOUDS_AZUREBLOB_ACCOUNT}" \
    -jar /opt/s3proxy/s3proxy \
    --properties /dev/null

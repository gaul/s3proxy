#!/bin/sh

mkdir "${JCLOUDS_FILESYSTEM_BASEDIR}"

# Secret-bearing variables may come from mounted files instead of the
# environment, e.g. JCLOUDS_CREDENTIAL_FILE=/run/secrets/credential; the
# file wins when both are set.  Command substitution strips the trailing
# newline that secret files usually carry.
for var in S3PROXY_IDENTITY S3PROXY_CREDENTIAL S3PROXY_KEYSTORE_PASSWORD \
        S3PROXY_ENCRYPTED_BLOBSTORE_PASSWORD \
        S3PROXY_ENCRYPTED_BLOBSTORE_SALT \
        JCLOUDS_IDENTITY JCLOUDS_CREDENTIAL JCLOUDS_SESSION_TOKEN; do
    eval "file=\${${var}_FILE:-}"
    if [ -n "$file" ]; then
        eval "$var=\$(cat \"\$file\")"
        export "${var?}"
    fi
done

# Pass configuration as a properties file rather than -D flags so that
# credentials do not appear in the java command line, which is readable via
# ps or /proc by anything sharing the pid namespace.  System properties
# override the file, so S3PROXY_JAVA_OPTS -D flags still win.
umask 077
PROPERTIES_FILE=/tmp/s3proxy.properties
awk 'function esc(s) {
    gsub(/\\/, "\\\\", s);
    gsub(/\n/, "\\n", s);
    return s
}
function prop(key, var) {
    print key "=" esc(ENVIRON[var])
}
function propdef(key, var, def) {
    if (ENVIRON[var] == "") {
        print key "=" def
    } else {
        prop(key, var)
    }
}
BEGIN {
    prop("s3proxy.endpoint", "S3PROXY_ENDPOINT")
    prop("s3proxy.secure-endpoint", "S3PROXY_SECURE_ENDPOINT")
    prop("s3proxy.virtual-host", "S3PROXY_VIRTUALHOST")
    prop("s3proxy.keystore-path", "S3PROXY_KEYSTORE_PATH")
    prop("s3proxy.keystore-password", "S3PROXY_KEYSTORE_PASSWORD")
    prop("s3proxy.authorization", "S3PROXY_AUTHORIZATION")
    prop("s3proxy.identity", "S3PROXY_IDENTITY")
    prop("s3proxy.credential", "S3PROXY_CREDENTIAL")
    prop("s3proxy.cors-allow-all", "S3PROXY_CORS_ALLOW_ALL")
    prop("s3proxy.cors-allow-origins", "S3PROXY_CORS_ALLOW_ORIGINS")
    prop("s3proxy.cors-allow-methods", "S3PROXY_CORS_ALLOW_METHODS")
    prop("s3proxy.cors-allow-headers", "S3PROXY_CORS_ALLOW_HEADERS")
    prop("s3proxy.cors-exposed-headers", "S3PROXY_CORS_EXPOSED_HEADERS")
    prop("s3proxy.cors-allow-credential", "S3PROXY_CORS_ALLOW_CREDENTIAL")
    prop("s3proxy.ignore-unknown-headers", "S3PROXY_IGNORE_UNKNOWN_HEADERS")
    prop("s3proxy.encrypted-blobstore", "S3PROXY_ENCRYPTED_BLOBSTORE")
    prop("s3proxy.encrypted-blobstore-password",
        "S3PROXY_ENCRYPTED_BLOBSTORE_PASSWORD")
    prop("s3proxy.encrypted-blobstore-salt",
        "S3PROXY_ENCRYPTED_BLOBSTORE_SALT")
    propdef("s3proxy.v4-max-non-chunked-request-size",
        "S3PROXY_V4_MAX_NON_CHUNKED_REQ_SIZE", "134217728")
    propdef("s3proxy.v4-max-chunk-size", "S3PROXY_V4_MAX_CHUNK_SIZE",
        "16777216")
    propdef("s3proxy.read-only-blobstore", "S3PROXY_READ_ONLY_BLOBSTORE",
        "false")
    propdef("s3proxy.no-cache-blobstore", "S3PROXY_NO_CACHE_BLOBSTORE",
        "false")
    prop("s3proxy.maximum-timeskew", "S3PROXY_MAXIMUM_TIMESKEW")
    prop("s3proxy.metrics.enabled", "S3PROXY_METRICS_ENABLED")
    prop("s3proxy.metrics.port", "S3PROXY_METRICS_PORT")
    prop("s3proxy.metrics.host", "S3PROXY_METRICS_HOST")
    prop("s3proxy.service-path", "S3PROXY_SERVICE_PATH")
    prop("jclouds.provider", "JCLOUDS_PROVIDER")
    prop("jclouds.identity", "JCLOUDS_IDENTITY")
    prop("jclouds.credential", "JCLOUDS_CREDENTIAL")
    prop("jclouds.session-token", "JCLOUDS_SESSION_TOKEN")
    prop("jclouds.endpoint", "JCLOUDS_ENDPOINT")
    prop("jclouds.region", "JCLOUDS_REGION")
    prop("jclouds.filesystem.basedir", "JCLOUDS_FILESYSTEM_BASEDIR")
}' > "$PROPERTIES_FILE"

# Defaults precede S3PROXY_JAVA_OPTS so callers can override them: the last
# occurrence of an -XX flag wins and an explicit -Xmx beats MaxRAMPercentage.
exec java \
    -XX:MaxRAMPercentage=75 \
    -XX:+UseCompactObjectHeaders \
    $S3PROXY_JAVA_OPTS \
    -DLOG_LEVEL="${LOG_LEVEL}" \
    -jar /opt/s3proxy/s3proxy \
    --properties "$PROPERTIES_FILE"

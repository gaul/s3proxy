/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.SortedSetMultimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import com.google.common.net.PercentEscaper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class AwsSignature {
    private static final Logger logger = LoggerFactory.getLogger(
            AwsSignature.class);
    private static final PercentEscaper AWS_URL_PARAMETER_ESCAPER =
            new PercentEscaper("-_.~", false);
    private static final Set<String> SIGNED_SUBRESOURCES = ImmutableSet.of(
            "acl",
            "delete",
            "lifecycle",
            "location",
            "logging",
            "notification",
            "partNumber",
            "policy",
            "requestPayment",
            "response-cache-control",
            "response-content-disposition",
            "response-content-encoding",
            "response-content-language",
            "response-content-type",
            "response-expires",
            "torrent",
            "uploadId",
            "uploads",
            "versionId",
            "versioning",
            "versions",
            "website"
    );
    private static final Pattern REPEATING_WHITESPACE = Pattern.compile("\\s+");

    private AwsSignature() { }

    /**
     * Create Amazon V2 signature.  Reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
     */
    static String createAuthorizationSignature(
            HttpServletRequest request, String uri, String credential,
            boolean queryAuth, boolean bothDateHeader) {
        // sort Amazon headers
        SortedSetMultimap<String, String> canonicalizedHeaders =
                TreeMultimap.create();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            Collection<String> headerValues = Collections.list(
                    request.getHeaders(headerName));
            headerName = headerName.toLowerCase();
            if (!headerName.startsWith("x-amz-") || (bothDateHeader &&
                  headerName.equalsIgnoreCase(AwsHttpHeaders.DATE))) {
                continue;
            }
            if (headerValues.isEmpty()) {
                canonicalizedHeaders.put(headerName, "");
            }
            for (String headerValue : headerValues) {
                canonicalizedHeaders.put(headerName,
                        Strings.nullToEmpty(headerValue));
            }
        }

        // Build string to sign
        StringBuilder builder = new StringBuilder()
                .append(request.getMethod())
                .append('\n')
                .append(Strings.nullToEmpty(request.getHeader(
                        HttpHeaders.CONTENT_MD5)))
                .append('\n')
                .append(Strings.nullToEmpty(request.getHeader(
                        HttpHeaders.CONTENT_TYPE)))
                .append('\n');
        String expires = request.getParameter("Expires");
        if (queryAuth) {
            // If expires is not nil, then it is query string sign
            // If expires is nil, maybe also query string sign
            // So should check other accessid param, presign to judge.
            // not the expires
            builder.append(Strings.nullToEmpty(expires));
        }  else {
            if (!bothDateHeader) {
                if (canonicalizedHeaders.containsKey(AwsHttpHeaders.DATE)) {
                    builder.append("");
                } else {
                    builder.append(request.getHeader(HttpHeaders.DATE));
                }
            }  else {
                if (!canonicalizedHeaders.containsKey(AwsHttpHeaders.DATE)) {
                    builder.append(request.getHeader(AwsHttpHeaders.DATE));
                }  else {
                    // panic
                }
            }
        }

        builder.append('\n');
        for (Map.Entry<String, String> entry : canonicalizedHeaders.entries()) {
            builder.append(entry.getKey()).append(':')
                    .append(entry.getValue()).append('\n');
        }
        builder.append(uri);

        char separator = '?';
        List<String> subresources = Collections.list(
                request.getParameterNames());
        Collections.sort(subresources);
        for (String subresource : subresources) {
            if (SIGNED_SUBRESOURCES.contains(subresource)) {
                builder.append(separator).append(subresource);

                String value = request.getParameter(subresource);
                if (!"".equals(value)) {
                    builder.append('=').append(value);
                }
                separator = '&';
            }
        }

        String stringToSign = builder.toString();
        logger.trace("stringToSign: {}", stringToSign);

        // Sign string
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(credential.getBytes(
                    StandardCharsets.UTF_8), "HmacSHA1"));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] signMessage(byte[] data, byte[] key, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data);
    }

    private static String getMessageDigest(byte[] payload, String algorithm)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hash = md.digest(payload);
        return BaseEncoding.base16().lowerCase().encode(hash);
    }

    @Nullable
    private static List<String> extractSignedHeaders(String authorization) {
        int index = authorization.indexOf("SignedHeaders=");
        if (index < 0) {
            return null;
        }
        int endSigned = authorization.indexOf(',', index);
        if (endSigned < 0) {
            return null;
        }
        int startHeaders = authorization.indexOf('=', index);
        return Splitter.on(';').splitToList(authorization.substring(
                startHeaders + 1, endSigned));
    }

    private static String buildCanonicalHeaders(HttpServletRequest request,
            List<String> signedHeaders) {
        List<String> headers = new ArrayList<>(
                /*initialCapacity=*/ signedHeaders.size());
        for (String header : signedHeaders) {
            headers.add(header.toLowerCase());
        }
        Collections.sort(headers);

        StringBuilder headersWithValues = new StringBuilder();
        boolean firstHeader = true;
        for (String header : headers) {
            if (firstHeader) {
                firstHeader = false;
            } else {
                headersWithValues.append('\n');
            }
            headersWithValues.append(header);
            headersWithValues.append(':');

            boolean firstValue = true;
            for (String value : Collections.list(request.getHeaders(header))) {
                if (firstValue) {
                    firstValue = false;
                } else {
                    headersWithValues.append(',');
                }
                value = value.trim();
                if (!value.startsWith("\"")) {
                    value = REPEATING_WHITESPACE.matcher(value).replaceAll(" ");
                }
                headersWithValues.append(value);
            }
        }

        return headersWithValues.toString();
    }

    private static String buildCanonicalQueryString(HttpServletRequest request)
            throws UnsupportedEncodingException {
        // The parameters are required to be sorted
        List<String> parameters = Collections.list(request.getParameterNames());
        Collections.sort(parameters);
        List<String> queryParameters = new ArrayList<>();

        for (String key : parameters) {
            if (key.equals("X-Amz-Signature")) {
                continue;
            }
            // re-encode keys and values in AWS normalized form
            String value = request.getParameter(key);
            queryParameters.add(AWS_URL_PARAMETER_ESCAPER.escape(key) +
                    "=" + AWS_URL_PARAMETER_ESCAPER.escape(value));
        }
        return Joiner.on("&").join(queryParameters);
    }

    private static String createCanonicalRequest(HttpServletRequest request,
                                                 String uri, byte[] payload,
                                                 String hashAlgorithm)
            throws IOException, NoSuchAlgorithmException {
        String authorizationHeader = request.getHeader("Authorization");
        String xAmzContentSha256 = request.getHeader(
                AwsHttpHeaders.CONTENT_SHA256);
        if (xAmzContentSha256 == null) {
            xAmzContentSha256 = request.getParameter("X-Amz-SignedHeaders");
        }
        String digest;
        if (authorizationHeader == null) {
            digest = "UNSIGNED-PAYLOAD";
        } else if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(
                xAmzContentSha256)) {
            digest = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
        } else if ("UNSIGNED-PAYLOAD".equals(xAmzContentSha256)) {
            digest = "UNSIGNED-PAYLOAD";
        } else {
            digest = getMessageDigest(payload, hashAlgorithm);
        }
        List<String> signedHeaders;
        if (authorizationHeader != null) {
            signedHeaders = extractSignedHeaders(authorizationHeader);
        } else {
            signedHeaders = Splitter.on(';').splitToList(request.getParameter(
                    "X-Amz-SignedHeaders"));
        }

        /*
         * CORS Preflight
         *
         * The signature is based on the canonical request, which includes the
         * HTTP Method.
         * For presigned URLs, the method must be replaced for OPTIONS request
         * to match
         */
        String method = request.getMethod();
        if ("OPTIONS".equals(method)) {
            String corsMethod = request.getHeader(
                    HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD);
            if (corsMethod != null) {
                method = corsMethod;
            }
        }

        String canonicalRequest = Joiner.on("\n").join(
                method,
                uri,
                buildCanonicalQueryString(request),
                buildCanonicalHeaders(request, signedHeaders) + "\n",
                Joiner.on(';').join(signedHeaders),
                digest);

        return getMessageDigest(
                canonicalRequest.getBytes(StandardCharsets.UTF_8),
                hashAlgorithm);
    }

    /**
     * Create v4 signature.  Reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
     */
    static String createAuthorizationSignatureV4(
            HttpServletRequest request, S3AuthorizationHeader authHeader,
            byte[] payload, String uri, String credential)
            throws InvalidKeyException, IOException, NoSuchAlgorithmException,
            S3Exception {
        String canonicalRequest = createCanonicalRequest(request, uri, payload,
                authHeader.getHashAlgorithm());
        String algorithm = authHeader.getHmacAlgorithm();
        byte[] dateKey = signMessage(
                authHeader.getDate().getBytes(StandardCharsets.UTF_8),
                ("AWS4" + credential).getBytes(StandardCharsets.UTF_8),
                algorithm);
        byte[] dateRegionKey = signMessage(
                authHeader.getRegion().getBytes(StandardCharsets.UTF_8),
                dateKey,
                algorithm);
        byte[] dateRegionServiceKey = signMessage(
                authHeader.getService().getBytes(StandardCharsets.UTF_8),
                dateRegionKey, algorithm);
        byte[] signingKey = signMessage(
                "aws4_request".getBytes(StandardCharsets.UTF_8),
                dateRegionServiceKey, algorithm);
        String date = request.getHeader(AwsHttpHeaders.DATE);
        if (date == null) {
            date = request.getParameter("X-Amz-Date");
        }
        String signatureString = "AWS4-HMAC-SHA256\n" +
                date + "\n" +
                authHeader.getDate() + "/" + authHeader.getRegion() +
                "/s3/aws4_request\n" +
                canonicalRequest;
        byte[] signature = signMessage(
                signatureString.getBytes(StandardCharsets.UTF_8),
                signingKey, algorithm);
        return BaseEncoding.base16().lowerCase().encode(signature);
    }
}

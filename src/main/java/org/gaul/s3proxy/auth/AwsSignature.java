/*
 * Copyright 2014-2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.auth;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.net.HttpHeaders;
import com.google.common.net.PercentEscaper;

import jakarta.servlet.http.HttpServletRequest;

import org.gaul.s3proxy.AwsHttpHeaders;
import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AwsSignature {
    private static final Logger logger = LoggerFactory.getLogger(
            AwsSignature.class);
    private static final PercentEscaper AWS_URL_PARAMETER_ESCAPER =
            new PercentEscaper("-_.~", false);
    /**
     * The query parameters a V2 signature folds into its canonicalized
     * resource.  Unlike V4, which signs the whole query string, V2 signs only
     * the parameters named here, so one left out rides along uncovered: the
     * signature verifies without it, yet doHandle still branches on it.  Every
     * parameter that selects which operation runs therefore has to appear
     * here, or a signature good for one operation is good for another --
     * "?attributes" turning a signed GetObject into GetObjectAttributes,
     * "?encryption" turning a signed bucket write into PutBucketEncryption.
     * The parameters that merely shape a listing -- prefix, max-keys and the
     * rest -- do not belong here: they steer no operation, and V2 clients do
     * not sign them.  This is the V2 face of the flaw the unsigned x-amz-*
     * header check closes for V4.
     */
    private static final Set<String> SIGNED_SUBRESOURCES = Set.of(
            "acl",
            "attributes",
            "delete",
            "encryption",
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
    /** A SHA-256 as x-amz-content-sha256 spells it, as opposed to one of the
     *  UNSIGNED-PAYLOAD or STREAMING-* tokens that header also accepts. */
    private static final Pattern SHA256_HEX = Pattern.compile(
            "[0-9a-fA-F]{64}");

    private AwsSignature() { }

    /**
     * A computed signature together with the strings it was computed from.
     * S3 returns these alongside SignatureDoesNotMatch so a client can diff
     * them against its own and see where the two canonicalizations parted
     * ways, which is otherwise invisible: every mismatch, whatever its cause,
     * looks the same from outside.
     */
    public record SignatureDetail(String signature, String stringToSign,
            @Nullable String canonicalRequest) { }

    /**
     * Create Amazon V2 signature.  Reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
     */
    public static SignatureDetail createAuthorizationSignature(
            HttpServletRequest request, String uri, String credential,
            boolean queryAuth, boolean bothDateHeader) {
        // sort Amazon headers
        // Sorted by name; a header sent more than once keeps its values in
        // the order they arrived, joined by commas onto one line, as the
        // specification has it.  They were sorted and each given a line of
        // its own, which no client signs.
        SortedMap<String, List<String>> canonicalizedHeaders =
                new TreeMap<>();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            Collection<String> headerValues = Collections.list(
                    request.getHeaders(headerName));
            headerName = headerName.toLowerCase();
            if (!headerName.startsWith("x-amz-") || (bothDateHeader &&
                  headerName.equalsIgnoreCase(AwsHttpHeaders.DATE))) {
                continue;
            }
            List<String> values = canonicalizedHeaders.computeIfAbsent(
                    headerName, unused -> new ArrayList<>());
            for (String headerValue : headerValues) {
                values.add(Strings.nullToEmpty(headerValue));
            }
        }

        // Build string to sign
        var builder = new StringBuilder()
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
        for (var entry : canonicalizedHeaders.entrySet()) {
            builder.append(entry.getKey()).append(':')
                    .append(String.join(",", entry.getValue()))
                    .append('\n');
        }
        builder.append(uri);

        char separator = '?';
        List<String> subresources = Collections.list(
                request.getParameterNames());
        subresources.sort(Comparator.naturalOrder());
        for (String subresource : subresources) {
            if (SIGNED_SUBRESOURCES.contains(subresource)) {
                builder.append(separator).append(subresource);

                String value = request.getParameter(subresource);
                if (!"".equals(value)) {
                    checkNoEmbeddedSubresource(subresource, value);
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
        return new SignatureDetail(
                Base64.getEncoder().encodeToString(mac.doFinal(
                        stringToSign.getBytes(StandardCharsets.UTF_8))),
                stringToSign, /*canonicalRequest=*/ null);
    }

    /**
     * Refuse a subresource value that reads as further subresources.  V2
     * signs the values decoded, joined by '&' and '=' with nothing escaped,
     * so "partNumber=1%26uploadId%3DX" has the string to sign of
     * "partNumber=1&uploadId=X" yet carries no uploadId: a URL signed for
     * UploadPart would verify as a PutObject over the finished object.
     * Clients sign the values unescaped, so escaping them here is not an
     * option.  Instead refuse the one spelling with two readings, a value in
     * which a signed subresource name follows an ampersand, which leaves
     * every string to sign with a single set of parameters behind it.  Any
     * other ampersand, such as one in the filename of a
     * response-content-disposition, is unambiguous and left alone.
     */
    private static void checkNoEmbeddedSubresource(String subresource,
            String value) {
        int ampersand = value.indexOf('&');
        if (ampersand == -1) {
            return;
        }
        for (String parameter : Splitter.on('&').split(
                value.substring(ampersand + 1))) {
            int equals = parameter.indexOf('=');
            String name = equals == -1 ? parameter :
                    parameter.substring(0, equals);
            if (SIGNED_SUBRESOURCES.contains(name)) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
                        "The value of " + subresource + " must not contain" +
                        " the subresource " + name);
            }
        }
    }

    private static byte[] signMessage(byte[] data, byte[] key, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data);
    }

    /**
     * Derive the AWS SigV4 signing key from the credential and auth header.
     */
    public static byte[] deriveSigningKeyV4(S3AuthorizationHeader authHeader,
            String credential)
            throws InvalidKeyException, NoSuchAlgorithmException {
        // V4 headers always carry these fields
        String algorithm = requireNonNull(authHeader.getHmacAlgorithm());
        byte[] dateKey = signMessage(
                requireNonNull(authHeader.getDate()).getBytes(
                        StandardCharsets.UTF_8),
                ("AWS4" + credential).getBytes(StandardCharsets.UTF_8),
                algorithm);
        byte[] dateRegionKey = signMessage(
                requireNonNull(authHeader.getRegion()).getBytes(
                        StandardCharsets.UTF_8),
                dateKey,
                algorithm);
        byte[] dateRegionServiceKey = signMessage(
                requireNonNull(authHeader.getService()).getBytes(
                        StandardCharsets.UTF_8),
                dateRegionKey, algorithm);
        return signMessage(
                "aws4_request".getBytes(StandardCharsets.UTF_8),
                dateRegionServiceKey, algorithm);
    }

    private static String getMessageDigest(byte[] payload, String algorithm)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hash = md.digest(payload);
        return HexFormat.of().formatHex(hash);
    }

    /**
     * The payload hash a presigned URL pinned through x-amz-content-sha256,
     * or null when it pinned none.  Naming that header among the signed ones
     * commits the URL to a single body, which some signers express by putting
     * the hash on the payload line of the canonical request where
     * UNSIGNED-PAYLOAD would otherwise go.  So does stating the hash as a
     * query parameter of that name, which is where a presigner that moves the
     * x-amz-* headers into the query string leaves it: the signature covers
     * every parameter, so that one needs no mention among the signed headers.
     * A header the query string did not sign says nothing about how the URL
     * was signed and is ignored, as is one of the streaming tokens, whose
     * chunked body this path does not decode.
     */
    @Nullable
    public static String pinnedPayloadHash(HttpServletRequest request) {
        String signedHeaders = request.getParameter("X-Amz-SignedHeaders");
        if (signedHeaders == null) {
            return null;
        }
        boolean signed = false;
        for (String header : Splitter.on(';').split(signedHeaders)) {
            if (header.equalsIgnoreCase(AwsHttpHeaders.CONTENT_SHA256)) {
                signed = true;
                break;
            }
        }
        if (signed) {
            String value = request.getHeader(AwsHttpHeaders.CONTENT_SHA256);
            if (value != null && SHA256_HEX.matcher(value).matches()) {
                return value;
            }
        }
        // The parameter stands for the header, so it is spelled as loosely as
        // one: a presigner moves the name across in whatever case it had.
        for (String parameter : Collections.list(
                request.getParameterNames())) {
            if (!parameter.equalsIgnoreCase(AwsHttpHeaders.CONTENT_SHA256)) {
                continue;
            }
            String value = request.getParameter(parameter);
            if (value != null && SHA256_HEX.matcher(value).matches()) {
                return value;
            }
        }
        return null;
    }

    /**
     * The headers a request declares it signed, however it declares them, or
     * null when it declares none.
     */
    @Nullable
    private static List<String> signedHeaderNames(HttpServletRequest request,
            boolean presignedUrl) {
        // A presigned request is signed through the query string.  Any
        // Authorization header it also carries addresses something other than
        // this proxy, so it names neither the signed headers nor the payload
        // treatment and must not be read as though it did.
        String authorizationHeader = presignedUrl ? null :
                request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return extractSignedHeaders(authorizationHeader);
        }
        String param = request.getParameter("X-Amz-SignedHeaders");
        return param == null ? null : Splitter.on(';').splitToList(param);
    }

    /**
     * Signed headers the request does not carry.  Signing a header commits
     * the caller to sending it: a URL presigned with x-amz-content-sha256 and
     * then uploaded through an HTTP client that does not know to repeat it
     * canonicalizes to an empty value here and to the real one at the signer,
     * so the signatures cannot agree.  The comparison alone cannot say that,
     * so name the absent headers instead of leaving the caller to guess.
     */
    public static List<String> missingSignedHeaders(HttpServletRequest request,
            boolean presignedUrl) {
        List<String> signedHeaders = signedHeaderNames(request, presignedUrl);
        if (signedHeaders == null) {
            return List.of();
        }
        var missing = new ArrayList<String>();
        for (String header : signedHeaders) {
            if (request.getHeader(header) == null) {
                missing.add(header.toLowerCase());
            }
        }
        return missing;
    }

    /**
     * The x-amz-* headers the request carries but did not sign.  A V4
     * signature covers only the headers the request names in its signed
     * list, so one it does not name rides along uncovered and the signature
     * still verifies without it.  That is harmless for a header S3 merely
     * stores, but an x-amz-* header can steer the request itself --
     * x-amz-copy-source turns a PUT into a copy of another object,
     * x-amz-acl publishes what it writes -- so leaving one unsigned lets the
     * bearer of a URL signed for one thing ask for another.  S3 closes that
     * by requiring every x-amz-* header to be signed and refusing a request
     * that carries one it did not, so name them here for the refusal to
     * report.  Lower-cased and sorted, so the answer does not depend on how
     * the client happened to spell or order them.
     *
     * <p>The one exception is x-amz-content-sha256 on a request authorized
     * by its Authorization header.  Its value is the last line of the
     * canonical request, so the signature covers it whether or not the
     * signed list names it -- altering it breaks the signature -- and S3
     * accepts such a request.  A presigned URL has no such line unless it
     * signs the header, so there the rule stands.
     */
    public static List<String> unsignedRequestHeaders(
            HttpServletRequest request, boolean presignedUrl) {
        List<String> signedHeaders = signedHeaderNames(request, presignedUrl);
        var signed = new HashSet<String>();
        if (signedHeaders != null) {
            for (String header : signedHeaders) {
                signed.add(header.toLowerCase());
            }
        }
        var unsigned = new ArrayList<String>();
        for (String name : Collections.list(request.getHeaderNames())) {
            String lower = name.toLowerCase();
            if (!lower.startsWith("x-amz-") || signed.contains(lower)) {
                continue;
            }
            if (!presignedUrl &&
                    lower.equals(AwsHttpHeaders.CONTENT_SHA256)) {
                continue;
            }
            unsigned.add(lower);
        }
        unsigned.sort(Comparator.naturalOrder());
        return unsigned;
    }

    @Nullable
    private static List<String> extractSignedHeaders(String authorization) {
        int index = authorization.indexOf("SignedHeaders=");
        if (index < 0) {
            return null;
        }
        // the fields come in any order, so this may be the last
        int endSigned = authorization.indexOf(',', index);
        if (endSigned < 0) {
            endSigned = authorization.length();
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
        headers.sort(Comparator.naturalOrder());

        var headersWithValues = new StringBuilder();
        boolean firstHeader = true;
        for (String header : headers) {
            if (firstHeader) {
                firstHeader = false;
            } else {
                headersWithValues.append('\n');
            }
            headersWithValues.append(header);
            headersWithValues.append(':');

            List<String> values = Collections.list(request.getHeaders(header));
            // V4 signs the lines of a repeated header as one value joined
            // with commas, so "a" and "b" on two lines sign the same as
            // "a,b" on one.  The handlers read an x-amz-* header from its
            // first line alone, so a signed value cut at one of its commas
            // would verify and yet say something else -- an
            // x-amz-copy-source of bucket/a,b copying bucket/a.  Refuse the
            // repeat, save for the one such header the handlers read line
            // by line, which an AWS SDK may split.
            if (values.size() > 1 && header.startsWith("x-amz-") &&
                    !header.equals(AwsHttpHeaders.OBJECT_ATTRIBUTES)) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
                        "The request repeats a header it declares as" +
                        " signed: " + header);
            }

            boolean firstValue = true;
            for (String value : values) {
                if (firstValue) {
                    firstValue = false;
                } else {
                    headersWithValues.append(',');
                }
                // Quoted or not: the SDKs collapse every run of spaces
                // when they sign, so sparing a value that opens with a
                // quote signed a different string than the client had.
                String sent = value;
                value = REPEATING_WHITESPACE.matcher(value.trim())
                        .replaceAll(" ");
                // Every spelling of a run of whitespace signs as one space,
                // while the handlers read the header as it was sent: a URL
                // signed to copy bucket/a b would verify for, and copy, the
                // key with two spaces or a tab there instead.  Clients sign
                // the folded value, so refuse an x-amz-* header sent in any
                // spelling but that one.  User metadata is only stored, and
                // clients do send it unfolded.
                if (!value.equals(sent) && header.startsWith("x-amz-") &&
                        !header.startsWith("x-amz-meta-")) {
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
                            "A signed header carries whitespace other than" +
                            " single spaces, which the signature does not" +
                            " cover: " + header);
                }
                headersWithValues.append(value);
            }
        }

        return headersWithValues.toString();
    }

    private static String buildCanonicalQueryString(
            HttpServletRequest request) {
        // The parameters are required to be sorted
        List<String> parameters = Collections.list(request.getParameterNames());
        parameters.sort(Comparator.naturalOrder());
        List<String> queryParameters = new ArrayList<>();

        for (String key : parameters) {
            if (key.equals("X-Amz-Signature")) {
                continue;
            }
            // Every value of a parameter sent more than once, sorted, as
            // the client signs them.  Only the first was taken, so such a
            // request never verified -- and its later values went unsigned.
            String[] values = request.getParameterValues(key);
            List<String> escaped = new ArrayList<>();
            for (String value : values == null ? new String[] {""} : values) {
                // re-encode keys and values in AWS normalized form
                escaped.add(AWS_URL_PARAMETER_ESCAPER.escape(
                        Strings.nullToEmpty(value)));
            }
            escaped.sort(Comparator.naturalOrder());
            for (String value : escaped) {
                queryParameters.add(AWS_URL_PARAMETER_ESCAPER.escape(key) +
                        "=" + value);
            }
        }
        return String.join("&", queryParameters);
    }

    private static String createCanonicalRequest(HttpServletRequest request,
                                                 String uri, byte[] payload,
                                                 String hashAlgorithm,
                                                 boolean presignedUrl,
                                                 @Nullable String pinnedHash,
                                                 @Nullable String verifiedHash)
            throws IOException, NoSuchAlgorithmException {
        // A presigned request is signed through the query string.  Any
        // Authorization header it also carries addresses something other than
        // this proxy, so it names neither the signed headers nor the payload
        // treatment and must not be read as though it did.
        String authorizationHeader = presignedUrl ? null :
                request.getHeader("Authorization");
        String xAmzContentSha256 = request.getHeader(
                AwsHttpHeaders.CONTENT_SHA256);
        if (xAmzContentSha256 == null) {
            xAmzContentSha256 = request.getParameter("X-Amz-Content-Sha256");
        }
        String digest;
        if (authorizationHeader == null) {
            // A presigned URL leaves the payload out of the signature, save
            // for the pinned hash the caller asks about here.
            digest = pinnedHash != null ? pinnedHash : "UNSIGNED-PAYLOAD";
        } else if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(
                xAmzContentSha256)) {
            digest = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
        } else if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER".equals(
                xAmzContentSha256)) {
            digest = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
        } else if ("STREAMING-UNSIGNED-PAYLOAD-TRAILER".equals(xAmzContentSha256)) {
            digest = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
        } else if ("UNSIGNED-PAYLOAD".equals(xAmzContentSha256)) {
            digest = "UNSIGNED-PAYLOAD";
        } else if (verifiedHash != null) {
            // The caller already hashed the payload to check the
            // x-amz-content-sha256 header, so hashing it again here can only
            // repeat that answer.  Reuse it for the payload line; the hash a
            // request carries but the caller did not verify -- one whose
            // presigned parameters skipped the body -- never reaches here.
            digest = verifiedHash;
        } else {
            digest = getMessageDigest(payload, hashAlgorithm);
        }
        List<String> signedHeaders = signedHeaderNames(request, presignedUrl);
        if (signedHeaders == null) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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

        return String.join("\n",
                method,
                uri,
                buildCanonicalQueryString(request),
                buildCanonicalHeaders(request, signedHeaders) + "\n",
                String.join(";", signedHeaders),
                digest);
    }

    /**
     * Create v4 signature.  Reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
     */
    public static SignatureDetail createAuthorizationSignatureV4(
            HttpServletRequest request, S3AuthorizationHeader authHeader,
            byte[] payload, String uri, String credential,
            boolean presignedUrl, @Nullable String pinnedHash,
            @Nullable String verifiedHash)
            throws InvalidKeyException, IOException, NoSuchAlgorithmException {
        // V4 headers always carry these fields
        String hashAlgorithm = requireNonNull(authHeader.getHashAlgorithm());
        String canonicalRequest = createCanonicalRequest(request, uri, payload,
                hashAlgorithm, presignedUrl, pinnedHash, verifiedHash);
        String algorithm = requireNonNull(authHeader.getHmacAlgorithm());
        byte[] signingKey = deriveSigningKeyV4(authHeader, credential);
        String date = request.getHeader(AwsHttpHeaders.DATE);
        if (date == null) {
            date = request.getParameter("X-Amz-Date");
        }
        String signatureString = "AWS4-HMAC-SHA256\n" +
                date + "\n" +
                authHeader.getDate() + "/" + authHeader.getRegion() + "/" +
                authHeader.getService() + "/aws4_request\n" +
                getMessageDigest(canonicalRequest.getBytes(
                        StandardCharsets.UTF_8), hashAlgorithm);
        byte[] signature = signMessage(
                signatureString.getBytes(StandardCharsets.UTF_8),
                signingKey, algorithm);
        return new SignatureDetail(
                HexFormat.of().formatHex(signature),
                signatureString, canonicalRequest);
    }
}

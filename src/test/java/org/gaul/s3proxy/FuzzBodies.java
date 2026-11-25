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

package org.gaul.s3proxy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Splitter;

import org.gaul.s3proxy.HandlerFuzzTest.Header;
import org.gaul.s3proxy.HandlerFuzzTest.Parameter;
import org.gaul.s3proxy.blobstore.Constants;
import org.jspecify.annotations.Nullable;

/**
 * Request bodies built from a handful of choices rather than written byte
 * by byte.  The operations that read a body mostly stop at its parse: a
 * fuzzer writing bytes seldom forms the XML of a DeleteObjects or an ACL,
 * and never a multipart form whose policy is signed, so what lies past the
 * parse went unreached.  Each body here is well formed, and each choice in
 * it is one the operation accepts or, now and then, any value at all, so
 * that the fuzzer reaches the checks of each field rather than the
 * parser's refusal of the whole.
 *
 * <p>The choices come through {@link Choices}, so that a test can build
 * the body every choice would accept and see the operation succeed: a
 * template that drifted from what S3Proxy reads would otherwise go on
 * being refused without anyone noticing.
 */
final class FuzzBodies {
    private static final String XMLNS =
            " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
    private static final String BOUNDARY = "FuzzBoundary7MA4YWxkTrZu0gW";
    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter POLICY_EXPIRATION =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private FuzzBodies() { }

    /**
     * Where a body's choices come from: the fuzzer's input, or, in a test,
     * a script.  Each names what it chooses, which only the script reads.
     */
    interface Choices {
        boolean flag(String what);

        int count(String what, int min, int max);

        /** One of valid, or now and then any value. */
        String pick(String what, List<String> valid);

        byte[] bytes(String what, int maxLength);
    }

    enum Kind {
        COMPLETE_MULTIPART_UPLOAD,
        DELETE_OBJECTS,
        VERSIONING,
        ACL,
        ENCRYPTION,
        CREATE_BUCKET,
        POST_FORM
    }

    /**
     * A body and what it needs of the request around it: headers such as
     * its Content-MD5 and, when the body is to fit the operation that reads
     * it, that operation's method and subresource.
     */
    static final class Built {
        private final byte[] body;
        private final List<Header> headers;
        private final @Nullable String method;
        private final List<Parameter> parameters;
        private final boolean bucketLevel;
        private final boolean form;

        Built(byte[] body, List<Header> headers, @Nullable String method,
                List<Parameter> parameters, boolean bucketLevel,
                boolean form) {
            this.body = body;
            this.headers = headers;
            this.method = method;
            this.parameters = parameters;
            this.bucketLevel = bucketLevel;
            this.form = form;
        }

        byte[] body() {
            return body;
        }

        List<Header> headers() {
            return headers;
        }

        /** The method the body's operation takes, or null to keep any. */
        @Nullable String method() {
            return method;
        }

        /** The subresources the body's operation takes. */
        List<Parameter> parameters() {
            return parameters;
        }

        /** Whether the operation addresses the bucket rather than a key. */
        boolean bucketLevel() {
            return bucketLevel;
        }

        /**
         * Whether the body authenticates itself, as a browser form does, so
         * that the request carries no other signature.
         */
        boolean form() {
            return form;
        }
    }

    /**
     * Builds a body of the kind, or returns null when it needs a value no
     * answer has given yet, as a CompleteMultipartUpload needs an upload id
     * and the ETags of its parts.
     */
    static @Nullable Built build(Kind kind, Choices choices, String bucket,
            List<String> uploadIds, List<String> versionIds,
            List<String> eTags, String identity, String credential) {
        boolean fit = choices.flag("fit");
        return switch (kind) {
        case COMPLETE_MULTIPART_UPLOAD -> uploadIds.isEmpty() ||
                eTags.isEmpty() ? null :
                xml(choices, completeMultipartUpload(choices, eTags),
                        fit ? "POST" : null, fit ? List.of(new Parameter(
                                "uploadId", choices.pick("uploadId",
                                        uploadIds))) : List.of(), false);
        case DELETE_OBJECTS -> xml(choices,
                deleteObjects(choices, versionIds), fit ? "POST" : null,
                fit ? List.of(new Parameter("delete", null)) : List.of(),
                true);
        case VERSIONING -> xml(choices, versioning(choices),
                fit ? "PUT" : null,
                fit ? List.of(new Parameter("versioning", null)) : List.of(),
                true);
        case ACL -> xml(choices, accessControlPolicy(choices),
                fit ? "PUT" : null,
                fit ? List.of(new Parameter("acl", null)) : List.of(),
                fit && choices.flag("bucket acl"));
        case ENCRYPTION -> xml(choices, encryption(choices),
                fit ? "PUT" : null,
                fit ? List.of(new Parameter("encryption", null)) : List.of(),
                true);
        case CREATE_BUCKET -> xml(choices, createBucket(choices),
                fit ? "PUT" : null, List.of(), true);
        case POST_FORM -> postForm(choices, bucket, identity, credential);
        };
    }

    private static Built xml(Choices choices, String xml,
            @Nullable String method, List<Parameter> parameters,
            boolean bucketLevel) {
        byte[] body = xml.getBytes(StandardCharsets.UTF_8);
        var headers = new ArrayList<Header>();
        // DeleteObjects and the configurations require a digest, which
        // only a body built whole can carry
        if (choices.flag("Content-MD5")) {
            headers.add(new Header("Content-MD5",
                    Base64.getEncoder().encodeToString(md5(body))));
        }
        if (choices.flag("Content-Type")) {
            headers.add(new Header("Content-Type", "application/xml"));
        }
        return new Built(body, headers, method, parameters, bucketLevel,
                /*form=*/ false);
    }

    private static String xmlns(Choices choices) {
        return choices.flag("no xmlns") ? "" : XMLNS;
    }

    static String completeMultipartUpload(Choices choices,
            List<String> eTags) {
        var xml = new StringBuilder("<CompleteMultipartUpload")
                .append(xmlns(choices)).append('>');
        int partNumber = 0;
        for (String eTag : eTags) {
            ++partNumber;
            if (choices.flag("skip part")) {
                continue;
            }
            xml.append("<Part><PartNumber>")
                    .append(choices.pick("PartNumber",
                            List.of(String.valueOf(partNumber))))
                    .append("</PartNumber><ETag>")
                    .append(escape(choices.pick("ETag", List.of(eTag))))
                    .append("</ETag>");
            if (choices.flag("ChecksumCRC32")) {
                xml.append("<ChecksumCRC32>")
                        .append(escape(choices.pick("ChecksumCRC32",
                                List.of("AAAAAA=="))))
                        .append("</ChecksumCRC32>");
            }
            xml.append("</Part>");
        }
        return xml.append("</CompleteMultipartUpload>").toString();
    }

    private static String deleteObjects(Choices choices,
            List<String> versionIds) {
        var xml = new StringBuilder("<Delete").append(xmlns(choices))
                .append('>');
        if (choices.flag("Quiet")) {
            xml.append("<Quiet>").append(choices.pick("Quiet",
                    List.of("true", "false"))).append("</Quiet>");
        }
        int objects = choices.count("objects", 1, 3);
        for (int i = 0; i < objects; ++i) {
            xml.append("<Object><Key>")
                    .append(escape(choices.pick("Key",
                            List.of("key", "dir/key", "dir/", "absent"))))
                    .append("</Key>");
            if (choices.flag("VersionId")) {
                var ids = new ArrayList<>(versionIds);
                ids.add("null");
                xml.append("<VersionId>")
                        .append(escape(choices.pick("VersionId", ids)))
                        .append("</VersionId>");
            }
            xml.append("</Object>");
        }
        return xml.append("</Delete>").toString();
    }

    private static String versioning(Choices choices) {
        var xml = new StringBuilder("<VersioningConfiguration")
                .append(xmlns(choices)).append("><Status>")
                .append(choices.pick("Status",
                        List.of("Enabled", "Suspended")))
                .append("</Status>");
        if (choices.flag("MfaDelete")) {
            xml.append("<MfaDelete>").append(choices.pick("MfaDelete",
                    List.of("Disabled", "Enabled"))).append("</MfaDelete>");
        }
        return xml.append("</VersioningConfiguration>").toString();
    }

    private static String accessControlPolicy(Choices choices) {
        var xml = new StringBuilder("<AccessControlPolicy")
                .append(xmlns(choices)).append("><Owner><ID>")
                .append(escape(choices.pick("Owner",
                        List.of(Constants.OWNER_ID))))
                .append("</ID></Owner><AccessControlList>");
        int grants = choices.count("grants", 1, 3);
        for (int i = 0; i < grants; ++i) {
            String type = choices.pick("Grantee type",
                    List.of("CanonicalUser", "Group",
                            "AmazonCustomerByEmail"));
            String element = switch (type) {
            case "Group" -> "URI";
            case "AmazonCustomerByEmail" -> "EmailAddress";
            default -> "ID";
            };
            String grantee = switch (type) {
            case "Group" -> choices.pick("Group", List.of(
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/" +
                            "AuthenticatedUsers",
                    "http://acs.amazonaws.com/groups/s3/LogDelivery"));
            case "AmazonCustomerByEmail" -> choices.pick("Email",
                    List.of("user@example.com"));
            default -> choices.pick("Grantee ID",
                    List.of(Constants.OWNER_ID));
            };
            xml.append("<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/")
                    .append("XMLSchema-instance\" xsi:type=\"")
                    .append(escape(type)).append("\"><").append(element)
                    .append('>').append(escape(grantee)).append("</")
                    .append(element).append("></Grantee><Permission>")
                    .append(choices.pick("Permission", List.of(
                            "FULL_CONTROL", "READ", "WRITE", "READ_ACP",
                            "WRITE_ACP")))
                    .append("</Permission></Grant>");
        }
        return xml.append("</AccessControlList></AccessControlPolicy>")
                .toString();
    }

    private static String encryption(Choices choices) {
        var xml = new StringBuilder("<ServerSideEncryptionConfiguration")
                .append(xmlns(choices))
                .append("><Rule><ApplyServerSideEncryptionByDefault>")
                .append("<SSEAlgorithm>")
                .append(escape(choices.pick("SSEAlgorithm",
                        List.of("AES256", "aws:kms", "aws:kms:dsse"))))
                .append("</SSEAlgorithm>");
        if (choices.flag("KMSMasterKeyID")) {
            xml.append("<KMSMasterKeyID>")
                    .append(escape(choices.pick("KMSMasterKeyID",
                            List.of("alias/aws/s3"))))
                    .append("</KMSMasterKeyID>");
        }
        xml.append("</ApplyServerSideEncryptionByDefault>");
        if (choices.flag("BucketKeyEnabled")) {
            xml.append("<BucketKeyEnabled>")
                    .append(choices.pick("BucketKeyEnabled",
                            List.of("true", "false")))
                    .append("</BucketKeyEnabled>");
        }
        return xml.append("</Rule></ServerSideEncryptionConfiguration>")
                .toString();
    }

    private static String createBucket(Choices choices) {
        return "<CreateBucketConfiguration" + xmlns(choices) +
                "><LocationConstraint>" +
                escape(choices.pick("LocationConstraint",
                        List.of("", "us-east-1", "eu-west-1"))) +
                "</LocationConstraint></CreateBucketConfiguration>";
    }

    /** How a browser form authenticates, in its own fields. */
    private enum FormSigning { NONE, V2, V4 }

    /**
     * A browser upload: multipart form fields naming the key and what the
     * object is to carry, a policy listing the conditions they must meet,
     * and the policy's signature.  The signature is over the policy, so a
     * form that signs it gets past authentication into the conditions,
     * which are what this exists to reach.
     */
    private static Built postForm(Choices choices, String bucket,
            String identity, String credential) {
        var fields = new ArrayList<String[]>();
        var conditions = new ArrayList<String>();
        fields.add(new String[] {"key", choices.pick("key", List.of(
                "upload", "dir/upload", "upload/${filename}",
                "${filename}"))});
        if (!choices.flag("no bucket condition")) {
            conditions.add("{\"bucket\": \"" + json(choices.pick(
                    "bucket condition", List.of(bucket))) + "\"}");
        }
        conditions.add("[\"starts-with\", \"$key\", \"" + json(choices.pick(
                "key prefix", List.of("", "dir/", "upload"))) + "\"]");
        if (choices.flag("content-length-range")) {
            conditions.add("[\"content-length-range\", " +
                    choices.pick("minimum", List.of("0", "1")) + ", " +
                    choices.pick("maximum", List.of("1048576", "4")) + "]");
        }
        for (String field : List.of("Content-Type", "success_action_status",
                "x-amz-meta-fuzz", "acl", "Content-Disposition",
                "Cache-Control", "x-amz-storage-class", "Expires")) {
            if (!choices.flag(field)) {
                continue;
            }
            String value = choices.pick(field, switch (field) {
            case "Content-Type" -> List.of("text/plain", "text/html");
            case "success_action_status" -> List.of("201", "200", "204");
            case "acl" -> List.of("private", "public-read");
            case "Content-Disposition" -> List.of("attachment");
            case "Cache-Control" -> List.of("no-cache");
            case "x-amz-storage-class" -> List.of("STANDARD");
            case "Expires" -> List.of("Thu, 01 Dec 1994 16:00:00 GMT");
            default -> List.of("value");
            });
            fields.add(new String[] {field, value});
            if (!choices.flag("unconditioned " + field)) {
                conditions.add(choices.flag("starts-with " + field) ?
                        "[\"starts-with\", \"$" + json(field) + "\", \"\"]" :
                        "{\"" + json(field) + "\": \"" + json(value) +
                        "\"}");
            }
        }

        FormSigning signing = choices.flag("unsigned form") ?
                FormSigning.NONE : choices.flag("V2 form") ?
                FormSigning.V2 : FormSigning.V4;
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String amzDate = AMZ_DATE.format(now);
        String scope = amzDate.substring(0, 8) + "/us-east-1/s3/aws4_request";
        if (signing == FormSigning.V4) {
            for (String[] field : List.of(
                    new String[] {"x-amz-algorithm", "AWS4-HMAC-SHA256"},
                    new String[] {"x-amz-credential", identity + "/" + scope},
                    new String[] {"x-amz-date", amzDate})) {
                fields.add(field);
                conditions.add("{\"" + field[0] + "\": \"" + field[1] +
                        "\"}");
            }
        }
        String expiration = POLICY_EXPIRATION.format(
                choices.flag("expired") ? now.minusMinutes(5) :
                now.plusMinutes(5));
        String policy = Base64.getEncoder().encodeToString(
                ("{\"expiration\": \"" + expiration + "\", " +
                "\"conditions\": [" + String.join(", ", conditions) + "]}")
                .getBytes(StandardCharsets.UTF_8));
        switch (signing) {
        case V2 -> {
            fields.add(new String[] {"AWSAccessKeyId", identity});
            fields.add(new String[] {"policy", policy});
            fields.add(new String[] {"signature", Base64.getEncoder()
                    .encodeToString(hmac("HmacSHA1", credential.getBytes(
                            StandardCharsets.UTF_8), policy))});
        }
        case V4 -> {
            byte[] key = ("AWS4" + credential).getBytes(
                    StandardCharsets.UTF_8);
            for (String part : Splitter.on('/').split(scope)) {
                key = hmac("HmacSHA256", key, part);
            }
            fields.add(new String[] {"policy", policy});
            fields.add(new String[] {"x-amz-signature",
                    HexFormat.of().formatHex(hmac("HmacSHA256", key,
                            policy))});
        }
        default -> { }
        }

        var body = new ByteArrayOutputStream();
        for (String[] field : fields) {
            body.writeBytes(("--" + BOUNDARY + "\r\n" +
                    "Content-Disposition: form-data; name=\"" + field[0] +
                    "\"\r\n\r\n" + field[1] + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        body.writeBytes(("--" + BOUNDARY + "\r\n" +
                "Content-Disposition: form-data; name=\"file\"; " +
                "filename=\"" + choices.pick("filename",
                        List.of("file.txt")).replaceAll("[\"\r\n]", "") +
                "\"\r\nContent-Type: text/plain\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8));
        body.writeBytes(choices.bytes("file", 64));
        body.writeBytes(("\r\n--" + BOUNDARY + "--\r\n")
                .getBytes(StandardCharsets.UTF_8));
        return new Built(body.toByteArray(), List.of(new Header(
                "Content-Type", "multipart/form-data; boundary=" + BOUNDARY)),
                "POST", List.of(), /*bucketLevel=*/ true, /*form=*/ true);
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private static String json(String value) {
        var escaped = new StringBuilder();
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                escaped.append('\\').append(c);
            } else if (c < 0x20) {
                escaped.append("\\u%04x".formatted((int) c));
            } else {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }

    private static byte[] md5(byte[] body) {
        try {
            return MessageDigest.getInstance("MD5").digest(body);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] hmac(String algorithm, byte[] key, String data) {
        try {
            var mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }
}

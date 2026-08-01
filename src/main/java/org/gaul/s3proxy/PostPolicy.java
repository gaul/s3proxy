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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.jspecify.annotations.Nullable;

import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The base64 policy document a browser form POST carries, saying what the
 * upload it authorizes may contain.  The signature proves the document came
 * from someone holding the secret; this says whether the form that arrived is
 * the one the document describes.  Without it a signed policy authorizes any
 * upload at all, since the signature covers only the policy's own bytes.
 *
 * <p>A document the parser cannot make sense of is a 400, a well-formed one
 * that does not admit the request is a 403, and a payload outside the length
 * the document allows is a 400 naming which end it fell off.  That split is
 * what S3 answers and what a browser upload library expects.
 */
final class PostPolicy {
    /**
     * Fields a policy need not mention.  The first four carry the
     * authorization itself and cannot be constrained by what they authorize;
     * the x-amz-* four are their SigV4 spellings.  x-ignore-* is reserved for
     * callers to smuggle their own data past the check, and a checksum names
     * the payload the length condition already covers.
     */
    private static final Set<String> UNCONSTRAINED = Set.of(
            "awsaccesskeyid",
            "signature",
            "policy",
            "file",
            "x-amz-algorithm",
            "x-amz-credential",
            "x-amz-date",
            "x-amz-security-token",
            "x-amz-signature");
    private static final Set<String> UNCONSTRAINED_PREFIXES = Set.of(
            "x-amz-checksum-",
            "x-ignore-");
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final long NO_LIMIT = -1;

    private final Instant expiration;
    private final List<Condition> conditions;
    private final long minLength;
    private final long maxLength;

    private PostPolicy(Instant expiration, List<Condition> conditions,
            long minLength, long maxLength) {
        this.expiration = expiration;
        this.conditions = List.copyOf(conditions);
        this.minLength = minLength;
        this.maxLength = maxLength;
    }

    /**
     * A single condition, already lowercased on the field name since both the
     * name in the document and the name of the form field are compared without
     * regard to case, while the value is compared exactly.
     */
    private record Condition(boolean startsWith, String field, String value) {
        boolean matches(String actual) {
            return startsWith ? actual.startsWith(value) : actual.equals(value);
        }
    }

    /**
     * Read a policy, or say why it is not one.  Every failure here is a 400:
     * the document is the caller's own and a malformed one is a mistake in
     * building the form rather than a refusal to serve it.
     */
    static PostPolicy parse(byte[] base64) throws S3Exception {
        byte[] decoded;
        try {
            decoded = Base64.getMimeDecoder().decode(base64);
        } catch (IllegalArgumentException iae) {
            throw invalid("Invalid policy: not base64", iae);
        }

        JsonNode root;
        try {
            root = JSON_MAPPER.readTree(
                    new String(decoded, StandardCharsets.UTF_8));
        } catch (StreamReadException | DatabindException e) {
            throw invalid("Invalid policy: not JSON", e);
        }
        if (root == null || !root.isObject()) {
            throw invalid("Invalid policy: not a JSON object", null);
        }

        // Both names are matched exactly.  S3 reads a document spelling them
        // any other way as one that declares neither, which is a document
        // without an expiry and therefore no document at all.
        JsonNode expirationNode = root.get("expiration");
        if (expirationNode == null || !expirationNode.isString()) {
            throw invalid("Invalid policy: missing expiration", null);
        }
        Instant expiration;
        try {
            expiration = Instant.parse(expirationNode.stringValue());
        } catch (DateTimeParseException dtpe) {
            throw invalid("Invalid policy: expiration is not an ISO 8601" +
                    " instant: " + expirationNode.stringValue(), dtpe);
        }

        JsonNode conditionsNode = root.get("conditions");
        if (conditionsNode == null || !conditionsNode.isArray() ||
                conditionsNode.isEmpty()) {
            throw invalid("Invalid policy: missing conditions", null);
        }

        var conditions = new ArrayList<Condition>();
        long minLength = NO_LIMIT;
        long maxLength = NO_LIMIT;
        for (JsonNode node : conditionsNode) {
            if (node.isObject()) {
                // Exactly one, since the object form is shorthand for an eq
                // on the field it names.  An empty one names nothing and a
                // larger one leaves which field it constrains ambiguous.
                if (node.size() != 1) {
                    throw invalid("Invalid policy: a condition object must" +
                            " name exactly one field", null);
                }
                for (var entry : node.properties()) {
                    conditions.add(new Condition(/*startsWith=*/ false,
                            lower(entry.getKey()),
                            stringValue(entry.getValue())));
                }
            } else if (node.isArray() && node.size() == 3) {
                String operator = lower(stringValue(node.get(0)));
                if (operator.equals("content-length-range")) {
                    minLength = length(node.get(1));
                    maxLength = length(node.get(2));
                    if (minLength > maxLength) {
                        throw invalid("Invalid policy: content-length-range" +
                                " minimum exceeds its maximum", null);
                    }
                } else if (operator.equals("eq") ||
                        operator.equals("starts-with")) {
                    String field = stringValue(node.get(1));
                    if (!field.startsWith("$") || field.length() < 2) {
                        throw invalid("Invalid policy: condition names " +
                                field + " rather than a $field", null);
                    }
                    conditions.add(new Condition(
                            operator.equals("starts-with"),
                            lower(field.substring(1)),
                            stringValue(node.get(2))));
                } else {
                    throw invalid("Invalid policy: unknown condition " +
                            operator, null);
                }
            } else {
                throw invalid("Invalid policy: a condition is neither an" +
                        " object nor a three-element array", null);
            }
        }

        return new PostPolicy(expiration, conditions, minLength, maxLength);
    }

    /**
     * Say whether this form is the one the document describes.  Both
     * directions are checked: a condition naming a field the form omitted
     * fails, and so does a field the document never mentions, since a policy
     * that constrained only what it happened to list would let a caller add
     * anything beside it.
     *
     * @param fields form field names, lowercased, to their values, with
     *     {@code bucket} taken from the request URI rather than the form
     * @param contentLength the length of the payload actually uploaded
     */
    void evaluate(Map<String, String> fields, long contentLength)
            throws S3Exception {
        if (Instant.now().isAfter(expiration)) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                    "Invalid according to Policy: Policy expired.");
        }

        for (Condition condition : conditions) {
            String actual = fields.get(condition.field());
            if (actual == null) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                        "Invalid according to Policy: Policy Condition" +
                        " failed: the form did not send " +
                        condition.field() + ".");
            }
            if (!condition.matches(actual)) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                        "Invalid according to Policy: Policy Condition" +
                        " failed: [\"" +
                        (condition.startsWith() ? "starts-with" : "eq") +
                        "\", \"$" + condition.field() + "\", \"" +
                        condition.value() + "\"]");
            }
        }

        for (String field : fields.keySet()) {
            if (isUnconstrained(field)) {
                continue;
            }
            boolean covered = false;
            for (Condition condition : conditions) {
                if (condition.field().equals(field)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                        "Invalid according to Policy: Extra input fields:" +
                        " " + field);
            }
        }

        // Reported as a bad request rather than a refusal: the form was
        // entitled to upload, and only the size of what it sent is wrong.
        if (minLength != NO_LIMIT && contentLength < minLength) {
            throw new S3Exception(S3ErrorCode.ENTITY_TOO_SMALL,
                    "Your proposed upload is smaller than the minimum" +
                    " allowed size");
        }
        if (maxLength != NO_LIMIT && contentLength > maxLength) {
            throw new S3Exception(S3ErrorCode.ENTITY_TOO_LARGE,
                    "Your proposed upload exceeds the maximum allowed size");
        }
    }

    private static boolean isUnconstrained(String field) {
        if (UNCONSTRAINED.contains(field)) {
            return true;
        }
        for (String prefix : UNCONSTRAINED_PREFIXES) {
            if (field.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static long length(JsonNode node) throws S3Exception {
        long value;
        if (node.isIntegralNumber()) {
            value = node.longValue();
        } else if (node.isString()) {
            // Some form builders quote the bounds.
            try {
                value = Long.parseLong(node.stringValue());
            } catch (NumberFormatException nfe) {
                throw invalid("Invalid policy: content-length-range bound " +
                        node.stringValue() + " is not a number", nfe);
            }
        } else {
            throw invalid("Invalid policy: content-length-range bound is not" +
                    " a number", null);
        }
        if (value < 0) {
            throw invalid("Invalid policy: content-length-range bound " +
                    value + " is negative", null);
        }
        return value;
    }

    private static String stringValue(JsonNode node) throws S3Exception {
        if (node == null || !node.isString()) {
            throw invalid("Invalid policy: expected a string", null);
        }
        return node.stringValue();
    }

    private static String lower(String value) {
        return value.toLowerCase(Locale.ROOT);
    }

    private static S3Exception invalid(String message,
            @Nullable Throwable cause) {
        return cause == null ?
                new S3Exception(S3ErrorCode.INVALID_POLICY_DOCUMENT, message) :
                new S3Exception(S3ErrorCode.INVALID_POLICY_DOCUMENT, message,
                        cause);
    }
}

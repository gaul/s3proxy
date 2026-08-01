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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

/**
 * A signature over a policy proves only where the policy came from.  These
 * cover the separate question the policy exists to answer -- whether the form
 * that arrived is the one it describes -- and the line between a document that
 * cannot be read (400) and one that can be read and says no (403).
 */
public final class PostPolicyTest {
    private static final String FUTURE = Instant.now()
            .plus(1, ChronoUnit.HOURS).toString();

    /** The conditions every well-formed example here starts from. */
    private static String policy(String conditions) {
        return "{\"expiration\": \"" + FUTURE + "\", \"conditions\": [" +
                conditions + "]}";
    }

    private static PostPolicy parse(String json) throws S3Exception {
        return PostPolicy.parse(Base64.getEncoder().encode(
                json.getBytes(StandardCharsets.UTF_8)));
    }

    private static Map<String, String> fields(String... keysAndValues) {
        var map = new LinkedHashMap<String, String>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return map;
    }

    private static void assertCode(ThrowingCallable call, S3ErrorCode code) {
        assertThatThrownBy(call)
                .isInstanceOf(S3Exception.class)
                .satisfies(t -> assertThat(((S3Exception) t).getError())
                        .isEqualTo(code));
    }

    @Test
    public void testAcceptsAConformingForm() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"starts-with\", \"$key\", \"foo\"]," +
                "[\"content-length-range\", 0, 1024]"));
        policy.evaluate(fields("bucket", "buck", "key", "foo.txt"), 3);
    }

    /** Names are matched without regard to case; values are not. */
    @Test
    public void testFieldNamesAreCaseInsensitive() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bUcKeT\": \"buck\"}," +
                "[\"StArTs-WiTh\", \"$KeY\", \"foo\"]"));
        policy.evaluate(fields("bucket", "buck", "key", "foo.txt"), 3);
    }

    @Test
    public void testValuesAreCaseSensitive() throws Exception {
        PostPolicy policy = parse(policy("{\"bucket\": \"buck\"}"));
        assertCode(() -> policy.evaluate(fields("bucket", "BUCK"), 0),
                S3ErrorCode.ACCESS_DENIED);
    }

    /** A condition naming a field the form never sent. */
    @Test
    public void testConditionWithoutItsField() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"starts-with\", \"$x-amz-meta-foo\", \"bar\"]"));
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 0),
                S3ErrorCode.ACCESS_DENIED);
    }

    /**
     * The other direction, which is the one that matters: a policy that
     * constrained only the fields it happened to list would let a form add
     * anything beside them.
     */
    @Test
    public void testFieldWithoutItsCondition() throws Exception {
        PostPolicy policy = parse(policy("{\"bucket\": \"buck\"}"));
        assertCode(() -> policy.evaluate(
                fields("bucket", "buck", "acl", "public-read"), 0),
                S3ErrorCode.ACCESS_DENIED);
    }

    /** What carries the authorization cannot be constrained by it. */
    @Test
    public void testAuthorizationFieldsNeedNoCondition() throws Exception {
        PostPolicy policy = parse(policy("{\"bucket\": \"buck\"}"));
        policy.evaluate(fields(
                "bucket", "buck",
                "awsaccesskeyid", "identity",
                "signature", "c2ln",
                "policy", "cG9s",
                "x-amz-algorithm", "AWS4-HMAC-SHA256",
                "x-ignore-anything", "at all",
                "x-amz-checksum-crc32", "AAAAAA=="), 0);
    }

    @Test
    public void testExpiredPolicy() throws Exception {
        PostPolicy policy = parse("{\"expiration\": \"" +
                Instant.now().minus(1, ChronoUnit.HOURS) +
                "\", \"conditions\": [{\"bucket\": \"buck\"}]}");
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 0),
                S3ErrorCode.ACCESS_DENIED);
    }

    /**
     * A length outside the range is a bad request rather than a refusal: the
     * form was entitled to upload and only the size is wrong.
     */
    @Test
    public void testLengthOutsideItsRange() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"content-length-range\", 512, 1024]"));
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 3),
                S3ErrorCode.ENTITY_TOO_SMALL);
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 2048),
                S3ErrorCode.ENTITY_TOO_LARGE);
        policy.evaluate(fields("bucket", "buck"), 512);
        policy.evaluate(fields("bucket", "buck"), 1024);
    }

    /** Every way a document can fail to be one, all of them 400. */
    @Test
    public void testMalformedDocumentsAreBadRequests() {
        assertCode(() -> parse("not json at all"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("[]"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        // The two top-level names are matched exactly.
        assertCode(() -> parse("{\"EXPIRATION\": \"" + FUTURE +
                "\", \"conditions\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("{\"expiration\": \"" + FUTURE +
                "\", \"CONDITIONS\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("{\"conditions\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("{\"expiration\": \"" + FUTURE + "\"}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        // A date that is not ISO 8601, e.g. Python's str(datetime).
        assertCode(() -> parse("{\"expiration\": \"2026-08-01 12:00:00\"," +
                " \"conditions\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        // An object condition names exactly one field.
        assertCode(() -> parse(policy("{}")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("{\"a\": \"1\", \"b\": \"2\"}")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("[\"eq\", \"key\", \"foo\"]")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("[\"wat\", \"$key\", \"foo\"]")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("[\"content-length-range\", 0]")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("[\"content-length-range\", -1, 0]")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy("[\"content-length-range\", 10, 1]")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
    }

    /** Some form builders quote the bounds; S3 takes them either way. */
    @Test
    public void testQuotedLengthBounds() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"content-length-range\", \"0\", \"1024\"]"));
        policy.evaluate(fields("bucket", "buck"), 1024);
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 1025),
                S3ErrorCode.ENTITY_TOO_LARGE);
    }

    /**
     * A starts-with against the empty string admits anything, which is how a
     * form says a field may be present without saying what it holds.
     */
    @Test
    public void testStartsWithEmptyAdmitsAnything() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"starts-with\", \"$tagging\", \"\"]"));
        policy.evaluate(fields("bucket", "buck", "tagging", "<Tagging/>"), 0);
    }

    /** A $ in a value is literal, not a reference to anything. */
    @Test
    public void testDollarInAValueIsLiteral() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"starts-with\", \"$key\", \"\\\\$foo\"]"));
        policy.evaluate(fields("bucket", "buck", "key", "\\$foo.txt"), 0);
    }
}

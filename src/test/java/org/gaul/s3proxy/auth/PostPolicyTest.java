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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;
import org.junit.jupiter.api.Test;

/**
 * A signature over a policy proves only where the policy came from.  These
 * cover the separate question the policy exists to answer -- whether the form
 * that arrived is the one it describes -- and the line between a document that
 * cannot be read (400) and one that can be read and says no (403).
 */
public final class PostPolicyTest {
    /**
     * An expiration these examples never reach.  Read when a test runs rather
     * than when the class loads, which would date the whole suite from the
     * moment it was first touched.
     */
    private static String future() {
        return Instant.now().plus(1, ChronoUnit.HOURS).toString();
    }

    /** The conditions every well-formed example here starts from. */
    private static String policy(String conditions) {
        return "{\"expiration\": \"" + future() + "\", \"conditions\": [" +
                conditions + "]}";
    }

    private static PostPolicy parse(String json) {
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
                .isInstanceOf(S3ProxyException.class)
                .satisfies(t -> assertThat(((S3ProxyException) t).getError())
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
     * An empty starts-with allows the field any content, which S3 reads as
     * covering a form that never sends it -- the idiom the s3-tests use to
     * admit an optional x-amz-server-side-encryption field.  Present or
     * absent, the form conforms; only a constraining condition has to be
     * answered.
     */
    @Test
    public void testEmptyStartsWithCoversAnAbsentField() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"starts-with\", \"$x-amz-server-side-encryption\", \"\"]"));
        policy.evaluate(fields("bucket", "buck"), 0);
        policy.evaluate(fields("bucket", "buck",
                "x-amz-server-side-encryption", "AES256"), 0);
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

    /**
     * Several ranges all have to hold, as any other conditions do, in
     * whichever order the document lists them.  Keeping only the last would
     * let a general cap undo the stricter range before it.
     */
    @Test
    public void testEveryLengthRangeHasToHold() throws Exception {
        String strict = "[\"content-length-range\", 512, 1024]";
        String lax = "[\"content-length-range\", 0, 1048576]";
        for (String ranges : List.of(strict + "," + lax, lax + "," + strict)) {
            PostPolicy policy = parse(policy(
                    "{\"bucket\": \"buck\"}," + ranges));
            assertCode(() -> policy.evaluate(fields("bucket", "buck"), 511),
                    S3ErrorCode.ENTITY_TOO_SMALL);
            policy.evaluate(fields("bucket", "buck"), 512);
            policy.evaluate(fields("bucket", "buck"), 1024);
            assertCode(() -> policy.evaluate(fields("bucket", "buck"), 1025),
                    S3ErrorCode.ENTITY_TOO_LARGE);
        }
    }

    /** Ranges with nothing in common admit no length at all. */
    @Test
    public void testDisjointLengthRangesAdmitNothing() throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"content-length-range\", 0, 10]," +
                "[\"content-length-range\", 20, 30]"));
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 5),
                S3ErrorCode.ENTITY_TOO_SMALL);
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 15),
                S3ErrorCode.ENTITY_TOO_SMALL);
        assertCode(() -> policy.evaluate(fields("bucket", "buck"), 25),
                S3ErrorCode.ENTITY_TOO_LARGE);
    }

    /** Every way a document can fail to be one, all of them 400. */
    @Test
    public void testMalformedDocumentsAreBadRequests() {
        assertCode(() -> parse("not json at all"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("[]"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        // The two top-level names are matched exactly.
        assertCode(() -> parse("{\"EXPIRATION\": \"" + future() +
                "\", \"conditions\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("{\"expiration\": \"" + future() +
                "\", \"CONDITIONS\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("{\"conditions\": [{\"bucket\": \"buck\"}]}"),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse("{\"expiration\": \"" + future() + "\"}"),
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

    /**
     * A bound past what a long holds is as invalid as a negative one.  JSON
     * has no limit on an integer's size, and Jackson answered the request
     * for a long with an exception the handler did not expect: a 500.
     */
    @Test
    public void testLengthBoundBeyondLongIsInvalid() throws Exception {
        assertCode(() -> parse(policy(
                "[\"content-length-range\", 0, 99999999999999999999]")),
                S3ErrorCode.INVALID_POLICY_DOCUMENT);
        assertCode(() -> parse(policy(
                "[\"content-length-range\", 99999999999999999999, 0]")),
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

    /**
     * A Content-Type holding commas is a list, and a starts-with has to hold
     * for every member of it rather than for the string as a whole: a browser
     * takes the last member for the type of what it is served, so a prefix
     * met only by the first would let a policy for video/ store a page.
     */
    @Test
    public void testStartsWithHoldsForEveryContentTypeInAList()
            throws Exception {
        PostPolicy policy = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "[\"starts-with\", \"$Content-Type\", \"video/\"]," +
                "[\"starts-with\", \"$x-amz-meta-foo\", \"video/\"]"));
        policy.evaluate(fields("bucket", "buck",
                "content-type", "video/mp4",
                "x-amz-meta-foo", "video/mp4"), 0);
        policy.evaluate(fields("bucket", "buck",
                "content-type", "video/mp4,video/webm",
                "x-amz-meta-foo", "video/mp4"), 0);
        policy.evaluate(fields("bucket", "buck",
                "content-type", "video/mp4, video/webm",
                "x-amz-meta-foo", "video/mp4"), 0);
        for (String contentType : List.of(
                "text/html",
                "video/mp4,text/html",
                "video/mp4, text/html",
                "video/mp4,video/webm,text/html",
                "video/mp4,")) {
            assertCode(() -> policy.evaluate(fields("bucket", "buck",
                    "content-type", contentType,
                    "x-amz-meta-foo", "video/mp4"), 0),
                    S3ErrorCode.ACCESS_DENIED);
        }
        // Only Content-Type is a list; any other field is one string.
        policy.evaluate(fields("bucket", "buck",
                "content-type", "video/mp4",
                "x-amz-meta-foo", "video/mp4,text/html"), 0);

        // eq never was a prefix, and names the whole value.
        PostPolicy exact = parse(policy(
                "{\"bucket\": \"buck\"}," +
                "{\"Content-Type\": \"video/mp4,video/webm\"}"));
        exact.evaluate(fields("bucket", "buck",
                "content-type", "video/mp4,video/webm"), 0);
        assertCode(() -> exact.evaluate(fields("bucket", "buck",
                "content-type", "video/mp4"), 0),
                S3ErrorCode.ACCESS_DENIED);
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

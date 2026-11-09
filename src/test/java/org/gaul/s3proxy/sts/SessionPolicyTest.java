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

package org.gaul.s3proxy.sts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;

public final class SessionPolicyTest {
    private static final String OBJECT = "arn:aws:s3:::bucket/home/alice/a";

    @Test
    public void testWildcards() {
        assertThat(SessionPolicy.wildcardMatches("*", "")).isTrue();
        assertThat(SessionPolicy.wildcardMatches("a*c", "abbbc")).isTrue();
        assertThat(SessionPolicy.wildcardMatches("a*c", "abbbd")).isFalse();
        assertThat(SessionPolicy.wildcardMatches("a?c", "abc")).isTrue();
        assertThat(SessionPolicy.wildcardMatches("a?c", "ac")).isFalse();
        assertThat(SessionPolicy.wildcardMatches("a*b*c", "aXbYbZc")).isTrue();
        // no other character is special
        assertThat(SessionPolicy.wildcardMatches("a.c", "abc")).isFalse();
        assertThat(SessionPolicy.wildcardMatches("[a]", "a")).isFalse();
    }

    @Test
    public void testAllowAndDefaultDeny() {
        SessionPolicy policy = SessionPolicy.parse("""
                {"Version": "2012-10-17", "Statement": {"Effect": "Allow",
                 "Action": "s3:Get*",
                 "Resource": "arn:aws:s3:::bucket/home/alice/*"}}""");
        assertThat(policy.isAllowed("s3:GetObject", OBJECT, Map.of()))
                .isTrue();
        // actions compare without regard to case, as IAM's do
        assertThat(policy.isAllowed("S3:getobject", OBJECT, Map.of()))
                .isTrue();
        assertThat(policy.isAllowed("s3:PutObject", OBJECT, Map.of()))
                .isFalse();
        assertThat(policy.isAllowed("s3:GetObject",
                "arn:aws:s3:::bucket/home/bob/a", Map.of())).isFalse();
        // resources compare with case
        assertThat(policy.isAllowed("s3:GetObject",
                "arn:aws:s3:::bucket/HOME/alice/a", Map.of())).isFalse();
    }

    @Test
    public void testDenyWins() {
        SessionPolicy policy = SessionPolicy.parse("""
                {"Statement": [
                 {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
                 {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}""");
        assertThat(policy.isAllowed("s3:GetObject", OBJECT, Map.of()))
                .isFalse();
    }

    @Test
    public void testConditions() {
        SessionPolicy policy = SessionPolicy.parse("""
                {"Statement": {"Effect": "Allow", "Action": "s3:ListBucket",
                 "Resource": "arn:aws:s3:::bucket",
                 "Condition": {"StringLike": {"s3:prefix":
                   ["home/alice/*", "shared/"]},
                  "StringEquals": {"S3:Delimiter": "/"}}}}""");
        String bucket = "arn:aws:s3:::bucket";
        assertThat(policy.isAllowed("s3:ListBucket", bucket, Map.of(
                "s3:prefix", "home/alice/x", "s3:delimiter", "/"))).isTrue();
        assertThat(policy.isAllowed("s3:ListBucket", bucket, Map.of(
                "s3:prefix", "shared/", "s3:delimiter", "/"))).isTrue();
        assertThat(policy.isAllowed("s3:ListBucket", bucket, Map.of(
                "s3:prefix", "home/bob/", "s3:delimiter", "/"))).isFalse();
        // every condition must hold
        assertThat(policy.isAllowed("s3:ListBucket", bucket, Map.of(
                "s3:prefix", "home/alice/x"))).isFalse();
        // an absent key matches nothing
        assertThat(policy.isAllowed("s3:ListBucket", bucket, Map.of()))
                .isFalse();
    }

    @Test
    public void testDenyWithConditionAppliesOnlyWhenItHolds() {
        SessionPolicy policy = SessionPolicy.parse("""
                {"Statement": [
                 {"Effect": "Allow", "Action": "s3:ListBucket",
                  "Resource": "*"},
                 {"Effect": "Deny", "Action": "s3:ListBucket",
                  "Resource": "*", "Condition": {"StringLike":
                   {"s3:prefix": "private/*"}}}]}""");
        assertThat(policy.isAllowed("s3:ListBucket", "arn:aws:s3:::b",
                Map.of("s3:prefix", "public/"))).isTrue();
        assertThat(policy.isAllowed("s3:ListBucket", "arn:aws:s3:::b",
                Map.of("s3:prefix", "private/x"))).isFalse();
    }

    @Test
    public void testUnsupportedIsRefused() {
        for (String document : new String[] {
            "",
            "[]",
            "{}",
            "{\"Statement\": []}",
            "{\"Version\": \"2099-01-01\", \"Statement\": " + allow() + "}",
            "{\"Statement\": " + allow() + ", \"Extra\": 1}",
            "{\"Statement\": " + allow() + "} trailing",
            statement("\"NotAction\": \"s3:GetObject\", \"Resource\": \"*\""),
            statement("\"Action\": \"s3:GetObject\", \"NotResource\": \"*\""),
            statement("\"Action\": \"s3:GetObject\", \"Resource\": \"*\"," +
                    " \"Principal\": \"*\""),
            statement("\"Action\": \"iam:CreateUser\", \"Resource\": \"*\""),
            statement("\"Action\": \"s3:GetObject\"," +
                    " \"Resource\": \"arn:aws:sqs:::q\""),
            statement("\"Action\": \"s3:GetObject\"," +
                    " \"Resource\": \"arn:aws:s3:::b/${aws:username}/*\""),
            statement("\"Action\": [], \"Resource\": \"*\""),
            statement("\"Action\": [1], \"Resource\": \"*\""),
            statement("\"Resource\": \"*\""),
            statement("\"Action\": \"s3:GetObject\""),
            statement("\"Action\": \"s3:GetObject\", \"Resource\": \"*\"," +
                    " \"Condition\": {\"StringNotLike\":" +
                    " {\"s3:prefix\": \"a\"}}"),
            statement("\"Action\": \"s3:GetObject\", \"Resource\": \"*\"," +
                    " \"Condition\": {\"StringLike\":" +
                    " {\"aws:SourceIp\": \"a\"}}"),
            statement("\"Action\": \"s3:GetObject\", \"Resource\": \"*\"," +
                    " \"Condition\": {\"StringLike\": {}}"),
            // duplicate keys would let two readers see two policies
            "{\"Statement\": {\"Effect\": \"Deny\", \"Effect\": \"Allow\"," +
                    " \"Action\": \"*\", \"Resource\": \"*\"}}",
            "{\"Statement\": {\"Effect\": \"allow\", \"Action\": \"*\"," +
                    " \"Resource\": \"*\"}}",
        }) {
            assertThatThrownBy(() -> SessionPolicy.parse(document))
                    .as(document)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    public void testLengthCountsBytes() {
        String resource = "arn:aws:s3:::b/" + "\u00e9".repeat(1000);
        assertThatThrownBy(() -> SessionPolicy.parse(statement(
                "\"Action\": \"*\", \"Resource\": \"" + resource + "\"")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bytes");
    }

    @Test
    public void testTooLong() {
        // valid but for its length
        String document = "{\"Statement\": " + allow() + "}";
        SessionPolicy.parse(document);
        String padded = document + " ".repeat(
                SessionPolicy.MAX_LENGTH - document.length() + 1);
        assertThatThrownBy(() -> SessionPolicy.parse(padded))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bytes");
    }

    private static String allow() {
        return "{\"Effect\": \"Allow\", \"Action\": \"*\"," +
                " \"Resource\": \"*\"}";
    }

    private static String statement(String body) {
        return "{\"Statement\": {\"Effect\": \"Allow\", " + body + "}}";
    }
}

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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The session policy a temporary credential carries: the subset of the IAM
 * policy language that scopes an S3 caller to buckets, key prefixes and
 * operations.  A statement may Allow or Deny, name actions and resources with
 * the * and ? wildcards, and condition on the s3:prefix and s3:delimiter keys
 * a listing sends.  Anything outside that subset -- NotAction, Principal,
 * another condition key or operator, a policy variable -- is refused when the
 * policy is parsed rather than ignored when it is evaluated: a statement
 * dropped for being unrecognized would grant more, or deny less, than its
 * author wrote.
 *
 * <p>Evaluation follows IAM: an explicit Deny wins, otherwise an Allow
 * grants, and a request that no statement allows is denied.
 */
public final class SessionPolicy {
    /**
     * The most policy GetFederationToken accepts, in UTF-8 bytes.  AWS
     * counts characters, but a token carries bytes: counting characters let
     * a policy of 2048 three-byte characters make a token too long for the
     * request header that has to carry it.
     */
    public static final int MAX_LENGTH = 2048;

    private static final String S3_ARN_PREFIX = "arn:aws:s3:::";
    private static final Set<String> VERSIONS = Set.of(
            "2012-10-17", "2008-10-17");
    private static final Set<String> POLICY_FIELDS = Set.of(
            "Version", "Id", "Statement");
    private static final Set<String> STATEMENT_FIELDS = Set.of(
            "Sid", "Effect", "Action", "Resource", "Condition");
    private static final Set<String> CONDITION_OPERATORS = Set.of(
            "StringEquals", "StringLike");
    /** Condition keys, lower-cased: IAM compares their names that way. */
    private static final Set<String> CONDITION_KEYS = Set.of(
            "s3:prefix", "s3:delimiter");
    private static final JsonMapper MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();

    private final List<Statement> statements;

    private SessionPolicy(List<Statement> statements) {
        this.statements = List.copyOf(statements);
    }

    /**
     * Parse a policy document.
     *
     * @throws IllegalArgumentException naming what the document gets wrong
     *     or uses that is not supported
     */
    public static SessionPolicy parse(String document) {
        if (utf8Length(document) > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "Policy exceeds " + MAX_LENGTH + " bytes");
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(document);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("Policy is not valid JSON", e);
        }
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("Policy must be a JSON object");
        }
        checkFields(root, POLICY_FIELDS, "policy");
        JsonNode version = root.get("Version");
        if (version != null &&
                (!version.isString() ||
                        !VERSIONS.contains(version.asString()))) {
            throw new IllegalArgumentException(
                    "Unsupported policy Version: " + version);
        }
        JsonNode id = root.get("Id");
        if (id != null && !id.isString()) {
            throw new IllegalArgumentException("Id must be a string");
        }
        JsonNode statementNode = root.get("Statement");
        if (statementNode == null) {
            throw new IllegalArgumentException("Policy has no Statement");
        }
        var statements = new ArrayList<Statement>();
        if (statementNode.isArray()) {
            for (JsonNode node : statementNode) {
                statements.add(parseStatement(node));
            }
        } else {
            statements.add(parseStatement(statementNode));
        }
        if (statements.isEmpty()) {
            throw new IllegalArgumentException("Policy has no Statement");
        }
        return new SessionPolicy(statements);
    }

    /** The policy's length as GetFederationToken limits it. */
    public static int utf8Length(String document) {
        return document.getBytes(StandardCharsets.UTF_8).length;
    }

    /**
     * Whether the policy permits an action on a resource.
     *
     * @param action an IAM action such as s3:GetObject
     * @param resource the ARN the action names, e.g. arn:aws:s3:::bucket/key
     * @param context condition key values the request supplies, keyed by
     *     lower-cased name; a key the request does not supply is absent
     */
    public boolean isAllowed(String action, String resource,
            Map<String, String> context) {
        boolean allowed = false;
        for (Statement statement : statements) {
            if (!statement.matches(action, resource, context)) {
                continue;
            }
            if (!statement.allow()) {
                return false;
            }
            allowed = true;
        }
        return allowed;
    }

    private static Statement parseStatement(JsonNode node) {
        if (!node.isObject()) {
            throw new IllegalArgumentException("Statement must be an object");
        }
        checkFields(node, STATEMENT_FIELDS, "statement");
        JsonNode sid = node.get("Sid");
        if (sid != null && !sid.isString()) {
            throw new IllegalArgumentException("Sid must be a string");
        }
        JsonNode effectNode = node.get("Effect");
        if (effectNode == null || !effectNode.isString()) {
            throw new IllegalArgumentException("Statement has no Effect");
        }
        boolean allow = switch (effectNode.asString()) {
        case "Allow" -> true;
        case "Deny" -> false;
        default -> throw new IllegalArgumentException(
                "Invalid Effect: " + effectNode.asString());
        };

        var actions = new ArrayList<String>();
        for (String action : stringList(node.get("Action"), "Action")) {
            String lower = action.toLowerCase(Locale.ROOT);
            if (!lower.equals("*") && !lower.startsWith("s3:")) {
                throw new IllegalArgumentException(
                        "Only s3 actions are supported: " + action);
            }
            actions.add(lower);
        }

        var resources = new ArrayList<String>();
        for (String resource : stringList(node.get("Resource"), "Resource")) {
            if (!resource.equals("*") && !resource.startsWith(S3_ARN_PREFIX)) {
                throw new IllegalArgumentException(
                        "Only S3 resources are supported: " + resource);
            }
            if (resource.contains("${")) {
                throw new IllegalArgumentException(
                        "Policy variables are not supported: " + resource);
            }
            resources.add(resource);
        }

        var conditions = new ArrayList<Condition>();
        JsonNode conditionNode = node.get("Condition");
        if (conditionNode != null) {
            if (!conditionNode.isObject()) {
                throw new IllegalArgumentException(
                        "Condition must be an object");
            }
            for (Map.Entry<String, JsonNode> operator :
                    conditionNode.properties()) {
                if (!CONDITION_OPERATORS.contains(operator.getKey())) {
                    throw new IllegalArgumentException(
                            "Unsupported condition operator: " +
                            operator.getKey());
                }
                boolean like = operator.getKey().equals("StringLike");
                if (!operator.getValue().isObject() ||
                        operator.getValue().isEmpty()) {
                    throw new IllegalArgumentException(
                            "Condition operator must map keys to values");
                }
                for (Map.Entry<String, JsonNode> entry :
                        operator.getValue().properties()) {
                    String key = entry.getKey().toLowerCase(Locale.ROOT);
                    if (!CONDITION_KEYS.contains(key)) {
                        throw new IllegalArgumentException(
                                "Unsupported condition key: " +
                                entry.getKey());
                    }
                    List<String> values = stringList(entry.getValue(),
                            entry.getKey());
                    for (String value : values) {
                        if (value.contains("${")) {
                            throw new IllegalArgumentException(
                                    "Policy variables are not supported: " +
                                    value);
                        }
                    }
                    conditions.add(new Condition(key, like, values));
                }
            }
        }
        return new Statement(allow, actions, resources, conditions);
    }

    private static void checkFields(JsonNode node, Set<String> allowed,
            String what) {
        for (String name : node.propertyNames()) {
            if (!allowed.contains(name)) {
                throw new IllegalArgumentException(
                        "Unsupported " + what + " element: " + name);
            }
        }
    }

    /** A string or a non-empty array of strings, as IAM accepts either. */
    private static List<String> stringList(JsonNode node, String name) {
        if (node == null) {
            throw new IllegalArgumentException("Statement has no " + name);
        }
        var values = new ArrayList<String>();
        if (node.isString()) {
            values.add(node.asString());
        } else if (node.isArray() && !node.isEmpty()) {
            for (JsonNode element : node) {
                if (!element.isString()) {
                    throw new IllegalArgumentException(
                            name + " must contain only strings");
                }
                values.add(element.asString());
            }
        } else {
            throw new IllegalArgumentException(
                    name + " must be a string or a non-empty array of strings");
        }
        return values;
    }

    /**
     * Match IAM-style: * stands for any run of characters, including none,
     * and ? for exactly one.  Nothing else is special.
     */
    static boolean wildcardMatches(String pattern, String value) {
        int p = 0;
        int v = 0;
        int star = -1;
        int mark = 0;
        while (v < value.length()) {
            if (p < pattern.length() && (pattern.charAt(p) == '?' ||
                    pattern.charAt(p) == value.charAt(v))) {
                p++;
                v++;
            } else if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                mark = v;
            } else if (star >= 0) {
                p = star + 1;
                v = ++mark;
            } else {
                return false;
            }
        }
        while (p < pattern.length() && pattern.charAt(p) == '*') {
            p++;
        }
        return p == pattern.length();
    }

    private record Statement(boolean allow, List<String> actions,
            List<String> resources, List<Condition> conditions) {
        boolean matches(String action, String resource,
                Map<String, String> context) {
            String lowerAction = action.toLowerCase(Locale.ROOT);
            if (actions.stream().noneMatch(
                    a -> wildcardMatches(a, lowerAction))) {
                return false;
            }
            if (resources.stream().noneMatch(
                    r -> wildcardMatches(r, resource))) {
                return false;
            }
            return conditions.stream().allMatch(c -> c.matches(context));
        }
    }

    /**
     * One key under one operator.  The request's value must equal, or for
     * StringLike match, any of the listed values; a key the request does not
     * supply matches nothing, so the statement does not apply.
     */
    private record Condition(String key, boolean like, List<String> values) {
        boolean matches(Map<String, String> context) {
            String actual = context.get(key);
            if (actual == null) {
                return false;
            }
            return values.stream().anyMatch(value -> like ?
                    wildcardMatches(value, actual) : value.equals(actual));
        }
    }
}

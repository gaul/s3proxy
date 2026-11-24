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
import java.util.Base64;

import org.gaul.s3proxy.blobstore.S3Exceptions;

/**
 * Values written into response headers the way S3 writes them, since a
 * header value is ISO-8859-1 without control characters (RFC 9110 5.5) and
 * the values S3Proxy echoes need not be: a response-* override is whatever
 * the URL says, and a POST Object form field stores whatever the form held.
 * Jetty turns CR and LF into spaces, so a value cannot split a response,
 * but it passes the other control characters through, which a strict client
 * then refuses to parse.
 *
 * <p>Each rule below is what AWS was measured to answer, on 2026-11-24.
 */
final class HeaderValues {
    /** The longest encoded text of one RFC 2047 word: 75, less "=?", "?",
     * the encoding, "?", "?=", and the charset name "UTF-8". */
    private static final int ENCODED_WORD_TEXT = 75 - 7 - 5;
    private static final String Q_SPECIALS = "=_?";
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private HeaderValues() {
        throw new AssertionError("intentionally unimplemented");
    }

    /**
     * A response-* override.  A control character other than TAB becomes a
     * space; a character beyond ISO-8859-1 cannot be written at all, which
     * S3 refuses before it answers.
     */
    static String override(String value) {
        for (int i = 0; i < value.length(); ++i) {
            if (value.charAt(i) > 0xff) {
                throw S3Exceptions.invalidArgument(
                        "Header value cannot be represented using" +
                        " ISO-8859-1.");
            }
        }
        return spaceControls(value);
    }

    /**
     * A stored system header -- Content-Type, Content-Disposition and the
     * rest.  A control character other than TAB becomes a space and a
     * character beyond ISO-8859-1 a question mark, since the object was
     * accepted with it and refusing to read it would help no one.
     */
    static String stored(String value) {
        var out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < value.length() &&
                    Character.isLowSurrogate(value.charAt(i + 1))) {
                // one character, one question mark
                ++i;
                out.append('?');
            } else if (c > 0xff) {
                out.append('?');
            } else {
                out.append(isControl(c) ? ' ' : c);
            }
        }
        return out.toString();
    }

    /**
     * A user metadata value.  One that holds a character other than
     * printable US-ASCII, CR, LF and TAB is sent as RFC 2047 encoded words
     * of its UTF-8 bytes -- base64 where such characters are at least half
     * of it, Q encoding otherwise -- each word at most 75 characters, made
     * by halving the value until its words fit.  This is JavaMail's
     * MimeUtility.encodeText, which S3's answers match byte for byte.
     * A value that needs no encoding may still hold CR or LF, which become
     * spaces.
     */
    static String userMetadata(String value) {
        int nonAscii = 0;
        for (int i = 0; i < value.length(); ++i) {
            if (needsEncoding(value.charAt(i))) {
                ++nonAscii;
            }
        }
        if (nonAscii == 0) {
            return value.replace('\r', ' ').replace('\n', ' ');
        }
        boolean base64 = nonAscii >= value.length() - nonAscii;
        var out = new StringBuilder();
        encode(value, base64, /*first=*/ true, out);
        return out.toString();
    }

    private static void encode(String value, boolean base64, boolean first,
            StringBuilder out) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        int length = base64 ? (bytes.length + 2) / 3 * 4 :
                qEncodedLength(bytes);
        if (length > ENCODED_WORD_TEXT && value.length() > 1) {
            int split = value.length() / 2;
            if (Character.isHighSurrogate(value.charAt(split - 1))) {
                --split;
            }
            if (split > 0) {
                encode(value.substring(0, split), base64, first, out);
            }
            encode(value.substring(split), base64, /*first=*/ false, out);
            return;
        }
        if (!first) {
            out.append(' ');
        }
        out.append(base64 ? "=?UTF-8?B?" : "=?UTF-8?Q?");
        if (base64) {
            out.append(Base64.getEncoder().encodeToString(bytes));
        } else {
            for (byte b : bytes) {
                int c = b & 0xff;
                if (c == ' ') {
                    out.append('_');
                } else if (c < 0x20 || c >= 0x7f ||
                        Q_SPECIALS.indexOf(c) >= 0) {
                    out.append('=').append(HEX[c >> 4]).append(HEX[c & 0xf]);
                } else {
                    out.append((char) c);
                }
            }
        }
        out.append("?=");
    }

    private static int qEncodedLength(byte[] bytes) {
        int length = 0;
        for (byte b : bytes) {
            int c = b & 0xff;
            length += c < 0x20 || c >= 0x7f || Q_SPECIALS.indexOf(c) >= 0 ?
                    3 : 1;
        }
        return length;
    }

    /** Whether RFC 2047 must carry this character of a metadata value. */
    private static boolean needsEncoding(char c) {
        return c >= 0x7f || (c < 0x20 && c != '\r' && c != '\n' && c != '\t');
    }

    private static boolean isControl(char c) {
        return (c < 0x20 && c != '\t') || c == 0x7f;
    }

    private static String spaceControls(String value) {
        var out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            out.append(isControl(c) ? ' ' : c);
        }
        return out.toString();
    }
}

/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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

import com.google.common.base.CaseFormat;

public enum AuthenticationType {
    AWS_V2,
    AWS_V4,
    AWS_V2_OR_V4,
    NONE;

    static AuthenticationType fromString(String string) {
        return AuthenticationType.valueOf(CaseFormat.LOWER_HYPHEN.to(
                CaseFormat.UPPER_UNDERSCORE, string));
    }
}

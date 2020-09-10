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

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.Lists;

import org.junit.Before;
import org.junit.Test;

public final class CrossOriginResourceSharingRuleTest {
    private CrossOriginResourceSharing corsAll;
    private CrossOriginResourceSharing corsCfg;
    private CrossOriginResourceSharing corsOff;

    @Before
    public void setUp() throws Exception {
        // CORS Allow All
        corsAll = new CrossOriginResourceSharing();
        // CORS Configured
        corsCfg = new CrossOriginResourceSharing(
                Lists.newArrayList("https://example\\.com",
                        "https://.+\\.example\\.com",
                        "https://example\\.cloud"),
                Lists.newArrayList("GET", "PUT"),
                Lists.newArrayList("Accept", "Content-Type"));
        // CORS disabled
        corsOff = new CrossOriginResourceSharing(null, null, null);
    }

    @Test
    public void testCorsOffOrigin() throws Exception {
        String probe = "";
        assertThat(corsOff.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isFalse();
        probe = "https://example.com";
        assertThat(corsOff.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isFalse();
    }

    @Test
    public void testCorsOffMethod() throws Exception {
        String probe = "";
        assertThat(corsOff.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isFalse();
        probe = "GET";
        assertThat(corsOff.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isFalse();
    }

    @Test
    public void testCorsOffHeader() throws Exception {
        String probe = "";
        assertThat(corsOff.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
        probe = "Accept";
        assertThat(corsOff.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
        probe = "Accept, Content-Type";
        assertThat(corsOff.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
    }

    @Test
    public void testCorsAllOrigin() throws Exception {
        String probe = "";
        assertThat(corsAll.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isFalse();
        probe = "https://example.com";
        assertThat(corsAll.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isTrue();
        probe = "https://sub.example.com";
        assertThat(corsAll.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isTrue();
    }

    @Test
    public void testCorsAllMethod() throws Exception {
        String probe = "";
        assertThat(corsAll.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isFalse();
        probe = "PATCH";
        assertThat(corsAll.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isFalse();
        probe = "GET";
        assertThat(corsAll.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isTrue();
        probe = "PUT";
        assertThat(corsAll.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isTrue();
        probe = "POST";
        assertThat(corsAll.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isTrue();
    }

    @Test
    public void testCorsAllHeader() throws Exception {
        String probe = "";
        assertThat(corsAll.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
        probe = "Accept";
        assertThat(corsAll.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isTrue();
        probe = "Accept, Content-Type";
        assertThat(corsAll.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isTrue();
    }

    @Test
    public void testCorsCfgOrigin() throws Exception {
        String probe = "";
        assertThat(corsCfg.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isFalse();
        probe = "https://example.org";
        assertThat(corsCfg.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isFalse();
        probe = "https://example.com";
        assertThat(corsCfg.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isTrue();
        probe = "https://sub.example.com";
        assertThat(corsCfg.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isTrue();
        probe = "https://example.cloud";
        assertThat(corsCfg.isOriginAllowed(probe))
                .as("check '%s' as origin", probe).isTrue();
    }

    @Test
    public void testCorsCfgMethod() throws Exception {
        String probe = "";
        assertThat(corsCfg.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isFalse();
        probe = "PATCH";
        assertThat(corsCfg.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isFalse();
        probe = "GET";
        assertThat(corsCfg.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isTrue();
        probe = "PUT";
        assertThat(corsCfg.isMethodAllowed(probe))
                .as("check '%s' as method", probe).isTrue();
    }

    @Test
    public void testCorsCfgHeader() throws Exception {
        String probe = "";
        assertThat(corsCfg.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
        probe = "Accept-Language";
        assertThat(corsCfg.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
        probe = "Accept, Accept-Encoding";
        assertThat(corsCfg.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isFalse();
        probe = "Accept";
        assertThat(corsCfg.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isTrue();
        probe = "Accept, Content-Type";
        assertThat(corsCfg.isEveryHeaderAllowed(probe))
                .as("check '%s' as header", probe).isTrue();
    }
}

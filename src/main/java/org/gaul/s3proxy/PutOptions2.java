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

import javax.annotation.Nullable;

import com.google.common.util.concurrent.ListeningExecutorService;

import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.options.PutOptions;

/**
 * This class extends jclouds' PutOptions to support conditional put operations via
 * the If-Match and If-None-Match headers.
 */
public final class PutOptions2 extends PutOptions {
    @Nullable
    private String ifMatch;
    @Nullable
    private String ifNoneMatch;

    public PutOptions2() {
        super();
    }

    public PutOptions2(PutOptions options) {
        super(options.isMultipart(), options.getUseCustomExecutor(),
                options.getCustomExecutor());
        this.setBlobAccess(options.getBlobAccess());

        if (options instanceof PutOptions2) {
            PutOptions2 other = (PutOptions2) options;
            this.ifMatch = other.ifMatch;
            this.ifNoneMatch = other.ifNoneMatch;
        }
    }

    @Nullable
    public String getIfMatch() {
        return ifMatch;
    }

    public PutOptions2 setIfMatch(@Nullable String etag) {
        this.ifMatch = etag;
        return this;
    }

    @Nullable
    public String getIfNoneMatch() {
        return ifNoneMatch;
    }

    public PutOptions2 setIfNoneMatch(@Nullable String etag) {
        this.ifNoneMatch = etag;
        return this;
    }

    @Override
    public PutOptions2 setBlobAccess(BlobAccess blobAccess) {
        super.setBlobAccess(blobAccess);
        return this;
    }

    @Override
    public PutOptions2 multipart() {
        super.multipart();
        return this;
    }

    @Override
    public PutOptions2 multipart(boolean val) {
        super.multipart(val);
        return this;
    }

    @Override
    public PutOptions2 multipart(ListeningExecutorService customExecutor) {
        super.multipart(customExecutor);
        return this;
    }

    @Override
    public PutOptions2 setCustomExecutor(ListeningExecutorService customExecutor) {
        super.setCustomExecutor(customExecutor);
        return this;
    }

    @Override
    public String toString() {
        String s = super.toString();
        return s.substring(0, s.length() - 1) +
                ", ifMatch=" + ifMatch +
                ", ifNoneMatch=" + ifNoneMatch + "]";
    }
}

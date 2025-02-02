/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.nio2blob;

import com.google.inject.AbstractModule;
import com.google.inject.Scopes;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.attr.ConsistencyModel;

public final class FilesystemNio2BlobStoreContextModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(ConsistencyModel.class).toInstance(ConsistencyModel.STRICT);
        bind(BlobStore.class).to(FilesystemNio2BlobStore.class).in(Scopes.SINGLETON);
    }
}

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

import java.util.Map;

import org.jclouds.blobstore.BlobStore;

/**
 * BlobStoreLocator is used to find relevant blobstore,
 * and the EXPECTED AWS SIGNATURE for the current
 * request. BolbStoreLocator gives out the credential
 * during the process which then is used to construct
 * the EXPECTED AWS SIGNATURE. Then the EXPECTED AWS SIGNATURE
 * is compared with the one within the request,
 * and only if they match the blobstore is used.
 * The BlobStoreLocator uses the identity to find the
 * relevant blobstore and the relevant credential for it.
 */

public interface BlobStoreLocator {
    Map.Entry<String, BlobStore> locateBlobStore(String identity,
            String container, String blob);
}

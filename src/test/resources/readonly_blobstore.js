/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var newBlobStore = function(blobStore) {
    var readOnlyBlobStore = Java.extend(Java.type("org.jclouds.blobstore.util.ForwardingBlobStore"));
    return new readOnlyBlobStore(blobStore) {
        // container operations
        createContainerInLocation: function(location, container) {
            throw new java.lang.UnsupportedOperationException();
        },
        deleteContainer: function(container) {
            throw new java.lang.UnsupportedOperationException();
        },
        deleteContainerIfEmpty: function(container) {
            throw new java.lang.UnsupportedOperationException();
        },
        clearContainer: function(container) {
            throw new java.lang.UnsupportedOperationException();
        },
        setContainerAccess: function(container, access) {
            throw new java.lang.UnsupportedOperationException();
        },

        // object operations
        putBlob: function(containerName, blob) {
            throw new java.lang.UnsupportedOperationException();
        },
        removeBlob: function(containerName, blobName) {
            throw new java.lang.UnsupportedOperationException();
        },
        removeBlobs: function(containerName, iterable) {
            throw new java.lang.UnsupportedOperationException();
        },
        initiateMultipartUpload: function(containerName, blobMetadata, options) {
            throw new java.lang.UnsupportedOperationException();
        },
        abortMultipartUpload: function(mpu) {
            throw new java.lang.UnsupportedOperationException();
        },
        completeMultipartUpload: function(mpu, parts) {
            throw new java.lang.UnsupportedOperationException();
        },
        uploadMultipartPart: function(mpu, partNumber, payload) {
            throw new java.lang.UnsupportedOperationException();
        },
        setBlobAccess: function(container, blob, access) {
            throw new java.lang.UnsupportedOperationException();
        },
    }
}

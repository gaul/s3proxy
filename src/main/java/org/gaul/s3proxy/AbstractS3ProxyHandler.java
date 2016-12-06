/*
 * Copyright 2014-2016 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jclouds.blobstore.BlobStore;



public abstract class AbstractS3ProxyHandler {
    protected abstract void handleGetContainerAcl(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName) throws IOException;

    protected abstract void handleSetContainerAcl(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception;

    protected abstract void handleGetBlobAcl(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException;

    protected abstract void handleSetBlobAcl(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception;

    protected abstract void handleContainerList(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore) throws IOException;

    protected abstract void handleContainerLocation(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName) throws IOException;

    protected abstract void handleListMultipartUploads(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore,
            String container) throws IOException, S3Exception;

    protected abstract void handleContainerExists(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception;

    protected abstract void handleContainerCreate(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception;

    protected abstract void handleContainerDelete(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception;

    protected abstract void handleBlobList(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception;

    protected abstract void handleBlobRemove(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception;

    protected abstract void handleMultiBlobRemove(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String containerName) throws IOException;

    protected abstract void handleBlobMetadata(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception;

    protected abstract void handleGetBlob(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName, String blobName)
            throws IOException, S3Exception;

    protected abstract void handleCopyBlob(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String destContainerName, String destBlobName)
            throws IOException, S3Exception;

    protected abstract void handlePutBlob(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception;

    protected abstract void handlePostBlob(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore, String containerName)
            throws IOException, S3Exception;

    protected abstract void handleInitiateMultipartUpload(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName, String blobName)
            throws IOException, S3Exception;

    protected abstract void handleCompleteMultipartUpload(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore, String containerName,
            String blobName, String uploadId) throws IOException, S3Exception;

    protected abstract void handleAbortMultipartUpload(
            HttpServletRequest request,  HttpServletResponse response,
            BlobStore blobStore, String containerName, String blobName,
            String uploadId) throws IOException, S3Exception;

    protected abstract void handleListParts(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName, String uploadId) throws IOException, S3Exception;

    protected abstract void handleCopyPart(
            HttpServletRequest request, HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName, String uploadId) throws IOException, S3Exception;

    protected abstract void handleUploadPart(
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception;
}

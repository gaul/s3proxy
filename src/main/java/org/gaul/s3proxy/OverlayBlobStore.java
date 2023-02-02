/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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

import com.google.common.collect.ForwardingObject;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.*;
import org.jclouds.blobstore.options.*;
import org.jclouds.domain.Location;
import org.jclouds.filesystem.reference.FilesystemConstants;
import org.jclouds.io.Payload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.ExecutorService;



/** This class is a BlobStore wrapper which tracks write operations in the local filesystem. */
final class OverlayBlobStore extends ForwardingObject implements BlobStore {

    private static final Logger logger = LoggerFactory.getLogger(
            OverlayBlobStore.class);

    private final BlobStore filesystemBlobStore;
    private final BlobStore upstreamBlobStore;
    private final String maskSuffix;

    public OverlayBlobStore(BlobStore upstreamBlobStore, String overlayPath, String maskSuffix) {
        this.maskSuffix = maskSuffix;
        this.upstreamBlobStore = upstreamBlobStore;

        Properties properties = new Properties();
        properties.setProperty(FilesystemConstants.PROPERTY_BASEDIR, overlayPath);
        BlobStoreContext context = ContextBuilder.newBuilder("filesystem")
                .overrides(properties)
                .buildView(BlobStoreContext.class);
        filesystemBlobStore = context.getBlobStore();
    }

    protected BlobStore delegateUpstream() {
        return upstreamBlobStore;
    }

    @Override
    protected BlobStore delegate() {
        return this.filesystemBlobStore;
    }

    public BlobStore localBlobStore() {
        return this.filesystemBlobStore;
    }

    public static BlobStore newOverlayBlobStore(BlobStore blobStore, String overlayPath, String maskSuffix) {
        return new OverlayBlobStore(blobStore, overlayPath, maskSuffix);
    }

    @Override
    public BlobStoreContext getContext() {
        return delegate().getContext();
    }

    @Override
    public BlobBuilder blobBuilder(String name) {
        return delegate().blobBuilder(name);
    }

    @Override
    public Set<? extends Location> listAssignableLocations() {
        return delegate().listAssignableLocations();
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        PageSet<StorageMetadata> localSet = (PageSet<StorageMetadata>) delegate().list();
        PageSet<StorageMetadata> upstreamSet = (PageSet<StorageMetadata>) delegateUpstream().list();
        localSet.addAll(upstreamSet);
        return localSet;
    }

    @Override
    public boolean containerExists(String container) {
        if(delegate().containerExists(container)){
            return true;
        } else {
            return delegateUpstream().containerExists(container);
        }
    }

    @Override
    public boolean createContainerInLocation(Location location,
                                             String container) {
        return delegate().createContainerInLocation(location, container);
    }

    @Override
    public boolean createContainerInLocation(Location location,
                                             String container, CreateContainerOptions options) {
        // TODO: Simulate error when creating a bucket that already exists
        return delegate().createContainerInLocation(location, container);
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        return delegate().getContainerAccess(container);
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess
            containerAccess) {
        delegate().setContainerAccess(container, containerAccess);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        if(delegate().containerExists(container)){
            PageSet<StorageMetadata> localSet = (PageSet<StorageMetadata>) delegate().list(container);
            if(delegateUpstream().containerExists(container)){
                PageSet<StorageMetadata> upstreamSet = (PageSet<StorageMetadata>) delegateUpstream().list(container);
                return mergeAndFilterList(localSet, upstreamSet);
            }
            return localSet;
        } else if(delegateUpstream().containerExists(container)) {
            return delegateUpstream().list(container);
        } else {
            return null;
        }
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
                                                   ListContainerOptions options) {

        if(delegate().containerExists(container)){
            PageSet<StorageMetadata> localSet = (PageSet<StorageMetadata>) delegate().list(container, options);
            if(delegateUpstream().containerExists(container)){
                PageSet<StorageMetadata> upstreamSet = (PageSet<StorageMetadata>) delegateUpstream().list(container, options);
                return mergeAndFilterList(localSet, upstreamSet);
            }
            return localSet;
        } else if(delegateUpstream().containerExists(container)) {
            return delegateUpstream().list(container, options);
        } else {
            return null;
        }
    }

    @Override
    public void clearContainer(String container) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public void deleteContainer(String container) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public boolean directoryExists(String container, String directory) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public void createDirectory(String container, String directory) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public void deleteDirectory(String container, String directory) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public boolean blobExists(String container, String name) {
        if(delegate().blobExists(container, name)){
            return true;
        } else {
            return delegateUpstream().blobExists(container, name);
        }
    }

    private boolean ensureLocalContainerExistsIfUpstreamDoes(String container) {
        if(delegate().containerExists(container)){
            return true;
        } else {
            if(delegateUpstream().containerExists(container)){
                return delegate().createContainerInLocation(null, container);
            }
        }
        return false;
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        ensureLocalContainerExistsIfUpstreamDoes(containerName);
        // TODO: Simulate error when file already exists in upstream bucket
        if(isBlobMasked(containerName, blob.getMetadata().getName())){
            unmaskBlob(containerName, blob.getMetadata().getName());
        }
        return delegate().putBlob(containerName, blob);
    }

    @Override
    public String putBlob(String containerName, Blob blob,
                          PutOptions putOptions) {
        ensureLocalContainerExistsIfUpstreamDoes(containerName);
        // TODO: Simulate error when file already exists in upstream bucket
        if(isBlobMasked(containerName, blob.getMetadata().getName())){
            unmaskBlob(containerName, blob.getMetadata().getName());
        }
        return delegate().putBlob(containerName, blob, putOptions);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName, String toContainer, String toName,
                           CopyOptions options) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        // TODO: Find a better way to generate a 'not found error'
        if(isBlobMasked(container, name)){
            return delegate().blobMetadata(container, "oasiguaogiyhgoiayhsgdogDsfsd");
        }

        if(isBlobLocal(container, name)){
            return delegate().blobMetadata(container, name);
        } else if(delegateUpstream().blobExists(container, name)){
            return delegateUpstream().blobMetadata(container, name);
        } else {
            // Returns a "Not Found" error
            return delegate().blobMetadata(container, name);
        }
    }

    private Blob getBlobMasked(String containerName, String blobName, GetOptions getOptions){
        if(isBlobMasked(containerName, blobName)){
            // TODO: Simlulate an error without doing something like this
            return delegate().getBlob(containerName, "aslkghbfdalkbjhdblkdfhgbdfb");
        }

        BlobStore sourceStore = null;
        if(isBlobLocal(containerName, blobName)){
            sourceStore = delegate();
            logger.debug("[ensureBlobIsLocal]: Blob " + containerName + "/" + blobName + " returned from local storage");
        } else {
            sourceStore = delegateUpstream();
            logger.debug("[ensureBlobIsLocal]: Blob " + containerName + "/" + blobName + " returned from remote storage");
        }

        if(getOptions == null){
            return sourceStore.getBlob(containerName, blobName);
        } else {
            return sourceStore.getBlob(containerName, blobName, getOptions);
        }
    }

    @Override
    public Blob getBlob(String containerName, String blobName) {
        return getBlobMasked(containerName, blobName, null);
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
                        GetOptions getOptions) {
        return getBlobMasked(containerName, blobName, getOptions);
    }

    @Override
    public void removeBlob(String container, String name) {
        maskBlob(container, name);
        if(delegate().blobExists(container, name)){
            delegate().removeBlob(container, name);
        }
    }

    @Override
    public void removeBlobs(String container, Iterable<String> iterable) {
        for (String name : iterable) {
            maskBlob(container, name);
            if(delegate().blobExists(container, name)){
                delegate().removeBlob(container, name);
            }
        }
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public void setBlobAccess(String container, String name,
                              BlobAccess access) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public long countBlobs(String container) {
        return delegate().countBlobs(container);
    }

    @Override
    public long countBlobs(String container, ListContainerOptions options) {
        return delegate().countBlobs(container, options);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container, BlobMetadata blobMetadata, PutOptions options) {
        // TODO: Simulate error when file already exists in upstreamContainer
        return delegate().initiateMultipartUpload(container, blobMetadata, options);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        delegate().abortMultipartUpload(mpu);
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu, List<MultipartPart> parts) {
        return delegate().completeMultipartUpload(mpu, parts);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu, int partNumber, Payload payload) {
        // TODO: Simulate error when file already exists in upstreamContainer
        return delegate().uploadMultipartPart(mpu, partNumber, payload);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        return delegate().listMultipartUpload(mpu);
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        return delegate().listMultipartUploads(container);
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return delegate().getMinimumMultipartPartSize();
    }

    @Override
    public long getMaximumMultipartPartSize() {
        return delegate().getMaximumMultipartPartSize();
    }

    @Override
    public int getMaximumNumberOfParts() {
        return delegate().getMaximumNumberOfParts();
    }

    @Override
    public void downloadBlob(String container, String name, File destination) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public void downloadBlob(String container, String name, File destination, ExecutorService executor) {
        throw new RuntimeException(new S3Exception(S3ErrorCode.INVALID_REQUEST, "Not Implemented Yet" ));
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        return delegate().streamBlob(container, name);
    }

    @Override
    public InputStream streamBlob(String container, String name, ExecutorService executor) {
        return delegate().streamBlob(container, name, executor);
    }


    // Returns true if the provided Metadata is for a Maskfile
    private boolean isBlobMaskFile(StorageMetadata sm){
        return sm.getName().endsWith(this.maskSuffix);
    }

    // Returns the name of the Blob that a Maskfile belongs to
    private String getMaskedBlobFileName(String maskFileName){
        return maskFileName.replace(this.maskSuffix, "");
    }

    // Returns the Maskfile name for the provided Blob name
    private String getBlobMaskFileName(String name){
        return name + this.maskSuffix;
    }

    // Returns true if a Maskfile exists for the provided Blob
    private boolean isBlobMasked(String container, String name){
        if(delegate().containerExists(container)){
            return delegate().blobExists(container, getBlobMaskFileName(name));
        } else {
            return false;
        }
    }

    // Creates a Maskfile for the specified Blob
    private void maskBlob(String container, String name){
        if(isBlobMasked(container, name)){
            // If it's already masked, no need to do anything.
            logger.debug("[maskBlob]: Blob " + container + "/" + name + " already masked");
            return;
        } else if(delegateUpstream().blobExists(container, name)) {
            // If it exists upstream, create a maskFile
            BlobBuilder blobBuilder = blobBuilder(getBlobMaskFileName(name)).payload("");
            delegate().putBlob(container, blobBuilder.build());
            logger.debug("[maskBlob]: Blob " + container + "/" + name + " successfully masked");
        } else {
            // Nothing
            return;
        }
    }

    // Removes the Maskfile for the specified Blob
    private void unmaskBlob(String container, String name){
        if(isBlobMasked(container, name)){
            delegate().removeBlob(container, getBlobMaskFileName(name));
            logger.debug("[unmaskBlob]: Blob " + container + "/" + name + " successfully unmasked");
            return;
        } else {
            logger.debug("[unmaskBlob]: Blob " + container + "/" + name + " is not masked");
        }
    }

    // Returns true if the specified Blob is available in the local backend
    private boolean isBlobLocal(String container, String name){
        if(delegate().containerExists(container)) {
            return delegate().blobExists(container, name);
        } else {
            return false;
        }
    }

    private PageSet<? extends StorageMetadata> mergeAndFilterList(PageSet<StorageMetadata> localSet, PageSet<StorageMetadata> upstreamSet){
        List<String> maskedBlobNames = new ArrayList<String>();
        List<String> localBlobNames = new ArrayList<String>();

        // TODO: This is a pretty terrible solution performance-wide
        //
        // Build a list of masked blobs and remove the maskfiles themselves from the localSet
        for (Iterator<StorageMetadata> iterator = localSet.iterator(); iterator.hasNext();) {
            StorageMetadata sm = iterator.next();
            if(isBlobMaskFile(sm)){
                String maskedFile = getMaskedBlobFileName(sm.getName());
                logger.info("[mergeAndFilterList]: Blob " + sm.getName() + " is a maskfile for " + maskedFile);
                maskedBlobNames.add(maskedFile);
                iterator.remove();
            } else {
                localBlobNames.add(sm.getName());
            }
        }

        // Remove any masked files from the upstream list, and any files that exist in local storage
        for (Iterator<StorageMetadata> iterator = upstreamSet.iterator(); iterator.hasNext();) {
            StorageMetadata sm = iterator.next();
            if(maskedBlobNames.contains(sm.getName())){
                logger.warn("[mergeAndFilterList]: Blob " + sm.getName() + " is masked, removing from list.");
                iterator.remove();
            } else if(localBlobNames.contains(sm.getName())){
                logger.info("[mergeAndFilterList]: Blob " + sm.getName() + " exists both locally and upstream. Using local copy.");
                iterator.remove();
            }
        }
        localSet.addAll(upstreamSet);
        return localSet;
    }

}

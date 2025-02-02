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

package org.gaul.s3proxy.crypto;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.SortedMap;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

@ThreadSafe
public class DecryptionInputStream extends FilterInputStream {

    // the cipher engine to use to process stream data
    private final Cipher cipher;

    // the secret key
    private final SecretKey key;

    // the list of parts we expect in the stream
    private final SortedMap<Integer, PartPadding> parts;

    /* the buffer holding data that have been read in from the
       underlying stream, but have not been processed by the cipher
       engine. */
    private final byte[] ibuffer = new byte[4096];

    // having reached the end of the underlying input stream
    private boolean done;

    /* the buffer holding data that have been processed by the cipher
       engine, but have not been read out */
    private byte[] obuffer;
    // the offset pointing to the next "new" byte
    private int ostart;
    // the offset pointing to the last "new" byte
    private int ofinish;
    // stream status
    private boolean closed;
    // the current part
    private int part;
    // the remaining bytes of the current part
    private long partBytesRemain;

    /**
     * Constructs a CipherInputStream from an InputStream and a
     * Cipher.
     * <br>Note: if the specified input stream or cipher is
     * null, a NullPointerException may be thrown later when
     * they are used.
     *
     * @param is            the to-be-processed input stream
     * @param key           the decryption key
     * @param parts         the list of parts
     * @param skipParts     the amount of parts to skip
     * @param skipPartBytes the amount of part bytes to skip
     * @throws IOException if cipher fails
     */
    public DecryptionInputStream(InputStream is, SecretKey key,
            SortedMap<Integer, PartPadding> parts, int skipParts,
            long skipPartBytes) throws IOException {
        super(is);
        in = is;
        this.parts = parts;
        this.key = key;

        PartPadding partPadding = parts.get(parts.size() - skipParts);

        try {
            // init the cipher
            cipher = Cipher.getInstance(Constants.AES_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, partPadding.getIv());
        } catch (Exception e) {
            throw new IOException(e);
        }

        // set the part to begin with
        part = parts.size() - skipParts;

        // adjust part size due to offset
        partBytesRemain = parts.get(part).getSize() - skipPartBytes;
    }

    /**
     * Ensure obuffer is big enough for the next update or doFinal
     * operation, given the input length <code>inLen</code> (in bytes)
     * The ostart and ofinish indices are reset to 0.
     *
     * @param inLen the input length (in bytes)
     */
    private void ensureCapacity(int inLen) {
        int minLen = cipher.getOutputSize(inLen);
        if (obuffer == null || obuffer.length < minLen) {
            obuffer = new byte[minLen];
        }
        ostart = 0;
        ofinish = 0;
    }

    /**
     * Private convenience function, read in data from the underlying
     * input stream and process them with cipher. This method is called
     * when the processed bytes inside obuffer has been exhausted.
     * <p>
     * Entry condition: ostart = ofinish
     * <p>
     * Exit condition: ostart = 0 AND ostart <= ofinish
     * <p>
     * return (ofinish-ostart) (we have this many bytes for you)
     * return 0 (no data now, but could have more later)
     * return -1 (absolutely no more data)
     * <p>
     * Note: Exceptions are only thrown after the stream is completely read.
     * For AEAD ciphers a read() of any length will internally cause the
     * whole stream to be read fully and verify the authentication tag before
     * returning decrypted data or exceptions.
     */
    private int getMoreData() throws IOException {
        if (done) {
            return -1;
        }

        int readLimit = ibuffer.length;
        if (partBytesRemain < ibuffer.length) {
            readLimit = (int) partBytesRemain;
        }

        int readin;
        if (partBytesRemain == 0) {
            readin = -1;
        } else {
            readin = in.read(ibuffer, 0, readLimit);
        }

        if (readin == -1) {
            ensureCapacity(0);
            try {
                ofinish = cipher.doFinal(obuffer, 0);
            } catch (Exception e) {
                throw new IOException(e);
            }

            int nextPart = part - 1;
            if (parts.containsKey(nextPart)) {
                // reset cipher
                PartPadding partPadding = parts.get(nextPart);
                try {
                    cipher.init(Cipher.DECRYPT_MODE, key, partPadding.getIv());
                } catch (Exception e) {
                    throw new IOException(e);
                }

                // update to the next part
                part = nextPart;

                // update the remaining bytes of the next part
                partBytesRemain = parts.get(nextPart).getSize();

                // Cannot call ByteStreams.skipFully since in may be shorter
                in.readNBytes(Constants.PADDING_BLOCK_SIZE);

                return ofinish;
            } else {
                done = true;
                if (ofinish == 0) {
                    return -1;
                } else {
                    return ofinish;
                }
            }
        }
        ensureCapacity(readin);
        try {
            ofinish = cipher.update(ibuffer, 0, readin, obuffer, ostart);
        } catch (ShortBufferException e) {
            throw new IOException(e);
        }

        partBytesRemain = partBytesRemain - readin;
        return ofinish;
    }

    /**
     * Reads the next byte of data from this input stream. The value
     * byte is returned as an <code>int</code> in the range
     * <code>0</code> to <code>255</code>. If no byte is available
     * because the end of the stream has been reached, the value
     * <code>-1</code> is returned. This method blocks until input data
     * is available, the end of the stream is detected, or an exception
     * is thrown.
     *
     * @return the next byte of data, or <code>-1</code> if the end of the
     * stream is reached.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public final int read() throws IOException {
        if (ostart >= ofinish) {
            // we loop for new data as the spec says we are blocking
            int i = 0;
            while (i == 0) {
                i = getMoreData();
            }
            if (i == -1) {
                return -1;
            }
        }
        return (int) obuffer[ostart++] & 0xff;
    }

    /**
     * Reads up to <code>b.length</code> bytes of data from this input
     * stream into an array of bytes.
     * <p>
     * The <code>read</code> method of <code>InputStream</code> calls
     * the <code>read</code> method of three arguments with the arguments
     * <code>b</code>, <code>0</code>, and <code>b.length</code>.
     *
     * @param b the buffer into which the data is read.
     * @return the total number of bytes read into the buffer, or
     * <code>-1</code> is there is no more data because the end of
     * the stream has been reached.
     * @throws IOException if an I/O error occurs.
     * @see java.io.InputStream#read(byte[], int, int)
     */
    @Override
    public final int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    /**
     * Reads up to <code>len</code> bytes of data from this input stream
     * into an array of bytes. This method blocks until some input is
     * available. If the first argument is <code>null,</code> up to
     * <code>len</code> bytes are read and discarded.
     *
     * @param b   the buffer into which the data is read.
     * @param off the start offset in the destination array
     *            <code>buf</code>
     * @param len the maximum number of bytes read.
     * @return the total number of bytes read into the buffer, or
     * <code>-1</code> if there is no more data because the end of
     * the stream has been reached.
     * @throws IOException if an I/O error occurs.
     * @see java.io.InputStream#read()
     */
    @Override
    public final int read(byte[] b, int off, int len) throws IOException {
        if (ostart >= ofinish) {
            // we loop for new data as the spec says we are blocking
            int i = 0;
            while (i == 0) {
                i = getMoreData();
            }
            if (i == -1) {
                return -1;
            }
        }
        if (len <= 0) {
            return 0;
        }
        int available = ofinish - ostart;
        if (len < available) {
            available = len;
        }
        if (b != null) {
            System.arraycopy(obuffer, ostart, b, off, available);
        }
        ostart = ostart + available;
        return available;
    }

    /**
     * Skips <code>n</code> bytes of input from the bytes that can be read
     * from this input stream without blocking.
     *
     * <p>Fewer bytes than requested might be skipped.
     * The actual number of bytes skipped is equal to <code>n</code> or
     * the result of a call to
     * {@link #available() available},
     * whichever is smaller.
     * If <code>n</code> is less than zero, no bytes are skipped.
     *
     * <p>The actual number of bytes skipped is returned.
     *
     * @param n the number of bytes to be skipped.
     * @return the actual number of bytes skipped.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public final long skip(long n) throws IOException {
        int available = ofinish - ostart;
        if (n > available) {
            n = available;
        }
        if (n < 0) {
            return 0;
        }
        ostart += (int) n;
        return n;
    }

    /**
     * Returns the number of bytes that can be read from this input
     * stream without blocking. The <code>available</code> method of
     * <code>InputStream</code> returns <code>0</code>. This method
     * <B>should</B> be overridden by subclasses.
     *
     * @return the number of bytes that can be read from this input stream
     * without blocking.
     */
    @Override
    public final int available() {
        return ofinish - ostart;
    }

    /**
     * Closes this input stream and releases any system resources
     * associated with the stream.
     * <p>
     * The <code>close</code> method of <code>CipherInputStream</code>
     * calls the <code>close</code> method of its underlying input
     * stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public final void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        in.close();

        // Throw away the unprocessed data and throw no crypto exceptions.
        // AEAD ciphers are fully readed before closing.  Any authentication
        // exceptions would occur while reading.
        if (!done) {
            ensureCapacity(0);
            try {
                cipher.doFinal(obuffer, 0);
            } catch (Exception e) {
                // Catch exceptions as the rest of the stream is unused.
            }
        }
        obuffer = null;
    }

    /**
     * Tests if this input stream supports the <code>mark</code>
     * and <code>reset</code> methods, which it does not.
     *
     * @return <code>false</code>, since this class does not support the
     * <code>mark</code> and <code>reset</code> methods.
     * @see java.io.InputStream#mark(int)
     * @see java.io.InputStream#reset()
     */
    @Override
    public final boolean markSupported() {
        return false;
    }
}

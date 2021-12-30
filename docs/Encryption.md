S3Proxy

# Encryption 

## Motivation 
The motivation behind this implementation is to provide a fully transparent and secure encryption to the s3 client while having the ability to write into different clouds.

## Cipher mode
The chosen cipher is ```AES/CFB/NoPadding``` because it provides the ability to read from an offset like in the middle of a ```Blob```.
While reading from an offset the decryption process needs to consider the previous 16 bytes of the AES block.

### Key generation
The encryption uses a 128-bit key that will be derived from a given password and salt in combination with random initialization vector that will be stored in each part padding.

## How a blob is encrypted 
Every uploaded part get a padding of 64 bytes that includes the necessary information for decryption. The input stream from a s3 client is passed through ```CipherInputStream``` and piped to append the 64 byte part padding at the end the encrypted stream. The encrypted input stream is then processed by the ```BlobStore``` to save the ```Blob```.

| Name      | Byte size | Description                                                    |
|-----------|-----------|----------------------------------------------------------------|
| Delimiter | 8 byte    | The delimiter is used to detect if the ```Blob``` is encrypted |
| IV        | 16 byte   | AES initialization vector                                      |
| Part      | 4 byte    | The part number                                                |
| Size      | 8 byte    | The unencrypted size of the ```Blob```                         |
| Version   | 2 byte    | Version can be used in the future if changes are necessary     |
| Reserved  | 26 byte   | Reserved for future use                                        |

### Multipart handling 
A single ```Blob``` can be uploaded by the client into multiple parts. After the completion all parts are concatenated into a single ```Blob```.
This procedure will result in multiple parts and paddings being held by a single ```Blob```.

### Single blob example
```
-------------------------------------
| ENCRYPTED BYTES         | PADDING |
-------------------------------------
```

### Multipart blob example
```
-------------------------------------------------------------------------------------
| ENCRYPTED BYTES | PADDING | ENCRYPTED BYTES | PADDING | ENCRYPTED BYTES | PADDING |
-------------------------------------------------------------------------------------
```

## How a blob is decrypted
The decryption is way more complex than the encryption. Decryption process needs to take care of the following circumstances:
- decryption of the entire ```Blob```
- decryption from a specific offset by skipping initial bytes 
- decryption of bytes by reading from the end (tail)
- decryption of a specific byte range like middle of the ```Blob```
- decryption of all previous situation by considering a underlying multipart ```Blob```

### Single blob decryption 
First the ```BlobMetadata``` is requested to get the encrypted ```Blob``` size. The last 64 bytes of ```PartPedding``` are fetched and inspected to detect if a decryption is necessary.
The cipher is than initialized with the IV and the key.

### Multipart blob decryption 
The process is similar to the single ```Blob``` decryption but with the difference that a list of parts is computed by fetching all ```PartPedding``` from end to the beginning.

## Blob suffix
Each stored ```Blob``` will get a suffix named ```.s3enc``` this helps to determine if a ```Blob``` is encrypted. For the s3 client the ```.s3enc``` suffix is not visible and the ```Blob``` size will always show the unencrypted size.  

## Tested jClouds provider
- S3
    - Minio
    - OBS from OpenTelekomCloud
- AWS S3
- Azure
- GCP
- Local

## Limitation 
- All blobs are encrypted with the same key that is derived from a given password 
- No support for re-encryption
- eTag always differs

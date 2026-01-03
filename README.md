# Spring S3 Presigned POST (SigV4) Presigner

A lightweight **S3 Presigned POST (multipart/form-data)** presigner for Spring Boot.  
Unlike `S3Presigner` (AWS SDK v2) which is commonly used for **presigned PUT/GET**, this project **builds the SigV4 policy and signature manually** so clients can upload directly to S3 using **HTML form-style POST**.

## Why Presigned POST?

With presigned PUT, size constraints are often enforced **after** upload (e.g., server-side HEAD check + delete), which can still incur transfer/storage/request costs.

Presigned POST allows you to enforce `content-length-range` directly in the S3 policy so that **S3 rejects oversized uploads at request time**.

## Features

- SigV4-based Presigned POST generation
- Policy conditions:
  - `bucket`
  - `key` (exact match)
  - `content-length-range` (1 ~ maxBytes)
  - `success_action_status` (default: 201)
  - `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`
  - STS session token support (`x-amz-security-token`) when using session credentials
  - Optional `Content-Type` condition
  - Optional SSE enforcement (`AES256` or `aws:kms` + KMS Key ID)
- Designed to be wired as a Spring Bean

## Requirements

- Java 17+
- Spring Boot 3.x
- AWS SDK v2 (credentials provider)
- Jackson `ObjectMapper`

## Server Usage
```java
PresignedPost presigned = s3PostPresigner.presignPost(
        PresignPostRequest.builder()
                .bucket(s3Properties.bucket())
                .key(key)
                .expiresIn(s3Properties.presignTtl())
                .maxBytes(s3Properties.maxUploadBytes())
                // .contentType("image/jpeg")
                // .serverSideEncryption("AES256") // or "aws:kms"
                // .sseKmsKeyId("your-kms-key-id")
                .successActionStatus("201")
                .build()
);
```

## Client Usage
Clients must upload as follows:
1. Call your server API to obtain { url, fields }
2. Send POST {url} with multipart/form-data
3. Add all fields exactly as returned
4. Add the actual binary file in the file part

## Security Notes
- content-length-range is evaluated by S3 during request validation. Oversized uploads are rejected by S3.
- Content-Type is not a full content verification mechanism (the client can still set it arbitrarily).
- In real systems, consider a post-upload “confirm” step on your server to:
  - validate object key naming
  - verify metadata/content-type if needed
  - enforce SSE configuration if required
  - finalize ownership/access control in your domain model

## Limitations / Extensibility
Current policy uses exact match for key.

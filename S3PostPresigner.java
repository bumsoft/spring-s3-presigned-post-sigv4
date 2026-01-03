import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.regions.Region;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Builder
public class S3PostPresigner {

    private final AwsCredentialsProvider credentialsProvider;
    private final Region region;
    private final ObjectMapper objectMapper;

    public PresignedPost presignPost(PresignPostRequest req) {
        validate(req);

        Instant now = Instant.now();
        Instant expiresAt = now.plus(req.getExpiresIn());

        ZonedDateTime zdt = ZonedDateTime.ofInstant(now, ZoneOffset.UTC);
        String amzDate = zdt.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String dateStamp = zdt.format(DateTimeFormatter.ofPattern("yyyyMMdd"));

        AwsCredentials creds = credentialsProvider.resolveCredentials();
        String accessKeyId = creds.accessKeyId();
        String secretAccessKey = creds.secretAccessKey();

        String sessionToken = null;
        if (creds instanceof AwsSessionCredentials sc) {
            sessionToken = sc.sessionToken();
        }

        String credentialScope = dateStamp + "/" + region.id() + "/s3/aws4_request";
        String xAmzCredential = accessKeyId + "/" + credentialScope;

        String url = toVirtualHostedStyleUrl(req.getBucket());

        // Policy JSON Config
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("expiration", DateTimeFormatter.ISO_INSTANT.format(expiresAt));

        List<Object> conditions = new ArrayList<>();
        conditions.add(Map.of("bucket", req.getBucket()));
        conditions.add(Map.of("key", req.getKey()));
        conditions.add(List.of("content-length-range", 1, req.getMaxBytes()));

        conditions.add(Map.of("x-amz-algorithm", "AWS4-HMAC-SHA256"));
        conditions.add(Map.of("x-amz-credential", xAmzCredential));
        conditions.add(Map.of("x-amz-date", amzDate));
        conditions.add(Map.of("success_action_status", req.getSuccessActionStatus()));

        if (sessionToken != null) {
            conditions.add(Map.of("x-amz-security-token", sessionToken));
        }

        // options
        if (req.getContentType() != null && !req.getContentType().isBlank()) {
            conditions.add(Map.of("Content-Type", req.getContentType()));
        }
        if (req.getServerSideEncryption() != null && !req.getServerSideEncryption().isBlank()) {
            conditions.add(Map.of("x-amz-server-side-encryption", req.getServerSideEncryption()));
            if ("aws:kms".equals(req.getServerSideEncryption())
                    && req.getSseKmsKeyId() != null && !req.getSseKmsKeyId().isBlank()) {
                conditions.add(Map.of("x-amz-server-side-encryption-aws-kms-key-id", req.getSseKmsKeyId()));
            }
        }

        policy.put("conditions", conditions);

        String policyBase64 = base64Json(policy);

        // SigV4 signature
        byte[] signingKey = getSignatureKey(secretAccessKey, dateStamp, region.id(), "s3");
        String signatureHex = toHex(hmacSha256(signingKey, policyBase64));

        // form fields 구성
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("key", req.getKey());
        fields.put("Policy", policyBase64);

        fields.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        fields.put("X-Amz-Credential", xAmzCredential);
        fields.put("X-Amz-Date", amzDate);
        fields.put("X-Amz-Signature", signatureHex);

        fields.put("success_action_status", req.getSuccessActionStatus());

        if (sessionToken != null) {
            fields.put("X-Amz-Security-Token", sessionToken);
        }
        if (req.getContentType() != null && !req.getContentType().isBlank()) {
            fields.put("Content-Type", req.getContentType());
        }
        if (req.getServerSideEncryption() != null && !req.getServerSideEncryption().isBlank()) {
            fields.put("x-amz-server-side-encryption", req.getServerSideEncryption());
            if ("aws:kms".equals(req.getServerSideEncryption())
                    && req.getSseKmsKeyId() != null && !req.getSseKmsKeyId().isBlank()) {
                fields.put("x-amz-server-side-encryption-aws-kms-key-id", req.getSseKmsKeyId());
            }
        }

        return new PresignedPost(url, fields, expiresAt, req.getMaxBytes());
    }

    private void validate(PresignPostRequest req) {
        if (req == null) throw new IllegalArgumentException("request is null");
        if (req.getBucket() == null || req.getBucket().isBlank()) throw new IllegalArgumentException("bucket is blank");
        if (req.getKey() == null || req.getKey().isBlank()) throw new IllegalArgumentException("key is blank");
        if (req.getExpiresIn() == null || req.getExpiresIn().isNegative() || req.getExpiresIn().isZero())
            throw new IllegalArgumentException("expiresIn must be positive");
        if (req.getMaxBytes() <= 0) throw new IllegalArgumentException("maxBytes must be > 0");
        if (req.getSuccessActionStatus() == null || req.getSuccessActionStatus().isBlank())
            throw new IllegalArgumentException("successActionStatus is blank");
    }

    private String toVirtualHostedStyleUrl(String bucket) {
        return "https://" + bucket + ".s3." + region.id() + ".amazonaws.com/";
    }

    private String base64Json(Map<String, Object> policy) {
        String json = null;
        try
        {
            json = objectMapper.writeValueAsString(policy);
        } catch (JsonProcessingException e)
        {
            throw new IllegalArgumentException("failed to build policy base64", e);
        }
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private String toJson(Object obj) {
        if (obj instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(escape(e.getKey().toString())).append("\":");
                sb.append(toJson(e.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        if (obj instanceof List<?> l) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object v : l) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(v));
            }
            sb.append("]");
            return sb.toString();
        }
        if (obj instanceof String s) return "\"" + escape(s) + "\"";
        if (obj instanceof Number || obj instanceof Boolean) return obj.toString();
        if (obj == null) return "null";
        return "\"" + escape(obj.toString()) + "\"";
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // SigV4 helpers
    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC calculation failed", e);
        }
    }

    private static byte[] getSignatureKey(String secretKey, String dateStamp, String regionName, String serviceName) {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, dateStamp);
        byte[] kRegion = hmacSha256(kDate, regionName);
        byte[] kService = hmacSha256(kRegion, serviceName);
        return hmacSha256(kService, "aws4_request");
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

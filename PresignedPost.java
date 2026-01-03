import lombok.Value;

import java.time.Instant;
import java.util.Map;

@Value
public class PresignedPost {
    String url; // https://{bucket}.s3.{region}.amazonaws.com/
    Map<String, String> fields;
    Instant expiresAt;
    long maxBytes;
}

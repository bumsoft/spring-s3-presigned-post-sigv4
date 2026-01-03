import lombok.Builder;
import lombok.Value;

import java.time.Duration;

@Value
@Builder
public class PresignPostRequest {
    String bucket;
    String key;
    
    Duration expiresIn;
    
    long maxBytes;
    
    @Builder.Default
    String successActionStatus = "201";

    // optional
    String contentType;
    String serverSideEncryption;
    String sseKmsKeyId;
}

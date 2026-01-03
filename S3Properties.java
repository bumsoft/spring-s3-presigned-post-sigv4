import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.s3")
public record S3Properties(
        String bucket,
        Duration presignTtl,
        Long maxUploadBytes
) {
}

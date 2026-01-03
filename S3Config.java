import com.example.RealConnect.S3.post.S3PostPresigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;

@Configuration
public class S3Config {

    @Bean
    public S3PostPresigner s3PostPresigner(ObjectMapper objectMapper)
    {
        return S3PostPresigner.builder()
                .region(Region.AP_NORTHEAST_2)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .objectMapper(objectMapper)
                .build();
    }
}

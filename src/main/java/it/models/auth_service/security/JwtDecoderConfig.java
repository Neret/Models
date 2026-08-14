package it.models.auth_service.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtDecoderConfig {

    @Value("${google.jwks.uri}")
    private String googleUri;

    @Value("${jwt.public.key}")
    private RSAPublicKey publicKey;

    @Bean
    public JwtDecoder googleJwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(googleUri).build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public JWKSet publicKey() {
        return new JWKSet(
            new RSAKey.Builder(publicKey).keyID("public-key").build()
        );
    }
}

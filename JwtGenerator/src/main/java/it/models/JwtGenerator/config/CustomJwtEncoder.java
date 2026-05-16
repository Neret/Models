package it.models.JwtGenerator.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class CustomJwtEncoder {

    @Bean
    public JWKSet gJwkSet() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.genKeyPair();
        KeyPair pair = generator.genKeyPair();
        JWK jwk = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
            .privateKey((RSAPrivateKey) pair.getPrivate())
            .build();
        return new JWKSet(jwk);
    }

    @Bean
    public JwtEncoder jEncoder() throws NoSuchAlgorithmException {
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(gJwkSet());
        return new NimbusJwtEncoder(jwks);
    }
}

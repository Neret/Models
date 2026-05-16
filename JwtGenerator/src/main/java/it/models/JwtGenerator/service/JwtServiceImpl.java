package it.models.JwtGenerator.service;

import com.nimbusds.jose.jwk.JWKSet;
import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import it.models.JwtGenerator.entity.JwtEntity;
import it.models.JwtGenerator.repository.JwtRepository;
import jakarta.transaction.Transactional;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class JwtServiceImpl implements JwtService {

    private final JwtRepository jwtRepository;
    private final JwtEncoder jwtEncoder;
    private final JWKSet jwkSet;

    private static final SecureRandom secureRandom = new SecureRandom();

    public JwtServiceImpl(
        JwtRepository jwtRepository,
        JwtEncoder jwtEncoder,
        JWKSet jwkSet
    ) {
        this.jwtRepository = jwtRepository;
        this.jwtEncoder = jwtEncoder;
        this.jwkSet = jwkSet;
    }

    private String generateOpaqueToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(randomBytes);
    }

    @Override
    public Token generateToken(UserProfile userProfile) {
        if (userProfile == null || userProfile.roles() == null) {
            throw new IllegalArgumentException(
                "Invalid UserProfile parameters"
            );
        }

        String opaqueAccess = generateOpaqueToken();
        String opaqueRefresh = generateOpaqueToken();

        JwtEntity entity = new JwtEntity();
        entity.setAccessToken(opaqueAccess);
        entity.setRefreshToken(opaqueRefresh);
        entity.setUserId(userProfile.id());
        entity.setEmittedAt(Instant.now());
        entity.setAccessExpiredAt(Instant.now().plus(15, ChronoUnit.MINUTES));
        entity.setRefreshExpiredAt(Instant.now().plus(7, ChronoUnit.DAYS));
        entity.setRoles(userProfile.roles());

        jwtRepository.save(entity);

        return new Token(opaqueAccess, opaqueRefresh);
    }

    @Override
    public Token refreshToken(Token token) {
        if (
            token == null ||
            token.refreshToken() == null ||
            token.refreshToken().isEmpty() ||
            token.accessToken() == null ||
            token.accessToken().isEmpty()
        ) {
            throw new IllegalArgumentException("Invalid Token");
        }

        Optional<JwtEntity> optionalOldEntity =
            jwtRepository.findByRefreshToken(token.refreshToken());
        if (optionalOldEntity.isEmpty()) {
            throw new IllegalArgumentException("Invalid Refresh Token");
        }

        JwtEntity oldEntity = optionalOldEntity.get();
        if (oldEntity.getRefreshExpiredAt().isBefore(Instant.now())) {
            jwtRepository.delete(oldEntity);
            throw new IllegalStateException(
                "Refresh Token Expired. Please login again."
            );
        }

        if (!oldEntity.getAccessToken().equals(token.accessToken())) {
            jwtRepository.delete(oldEntity);
            throw new IllegalArgumentException(
                "Token Mismatch: Possible token theft"
            );
        }

        String newOpaqueAccess = generateOpaqueToken();
        String newOpaqueRefresh = generateOpaqueToken();

        oldEntity.setAccessToken(newOpaqueAccess);
        oldEntity.setRefreshToken(newOpaqueRefresh);
        oldEntity.setEmittedAt(Instant.now());
        oldEntity.setAccessExpiredAt(
            Instant.now().plus(15, ChronoUnit.MINUTES)
        );
        oldEntity.setRefreshExpiredAt(Instant.now().plus(7, ChronoUnit.DAYS));

        jwtRepository.save(oldEntity);

        return new Token(newOpaqueAccess, newOpaqueRefresh);
    }

    @Override
    public String introspectToJwt(String opaqueAccessToken) {
        Optional<JwtEntity> optionalEntity = jwtRepository.findByAccessToken(
            opaqueAccessToken
        );

        if (optionalEntity.isEmpty()) {
            throw new IllegalArgumentException("Token not found or invalid");
        }

        JwtEntity entity = optionalEntity.get();
        if (entity.getAccessExpiredAt().isBefore(Instant.now())) {
            throw new IllegalStateException("Access Token Expired");
        }

        JwtClaimsSet set = JwtClaimsSet.builder()
            .issuer("token-service")
            .issuedAt(Instant.now())
            .expiresAt(entity.getAccessExpiredAt())
            .subject(String.valueOf(entity.getUserId()))
            .claim("scope", String.join(" ", entity.getRoles()))
            .build();

        return jwtEncoder
            .encode(JwtEncoderParameters.from(set))
            .getTokenValue();
    }

    @Override
    public void revokeToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Token not provided");
        }

        Optional<JwtEntity> optionalToken = jwtRepository.findByRefreshToken(
            refreshToken
        );

        if (optionalToken.isEmpty()) {
            throw new IllegalArgumentException("Token invalid or not found");
        }

        jwtRepository.delete(optionalToken.get());
    }

    @Override
    public JWKSet getPublic() {
        return jwkSet;
    }
}

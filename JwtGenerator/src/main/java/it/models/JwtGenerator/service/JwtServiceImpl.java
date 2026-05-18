package it.models.JwtGenerator.service;

import com.nimbusds.jose.jwk.JWKSet;
import it.models.JwtGenerator.dto.AccessToken;
import it.models.JwtGenerator.dto.RefreshToken;
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

    private String generateJwt(long userId, String roles) {
        if (roles == null || roles.isBlank()) {
            throw new IllegalArgumentException("Roles cannot be null or empty");
        }

        JwtClaimsSet set = JwtClaimsSet.builder()
            .issuer("token-service")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
            .subject(String.valueOf(userId))
            .claim("scope", roles)
            .build();

        return jwtEncoder
            .encode(JwtEncoderParameters.from(set))
            .getTokenValue();
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
        StringBuilder stringBuilder = new StringBuilder();

        for (String role : userProfile.roles()) {
            String tmp;
            if (role.startsWith("ROLE_")) tmp = "ROLE_" + role;
            else tmp = role;

            if (stringBuilder.length() > 0) {
                stringBuilder.append(" ");
            }
            stringBuilder.append(tmp);
        }

        String rolesString = stringBuilder.toString();
        String.join(" ", userProfile.roles());

        JwtEntity entity = new JwtEntity();
        entity.setAccessToken(opaqueAccess);
        entity.setRefreshToken(opaqueRefresh);
        entity.setUserId(userProfile.id());
        entity.setEmittedAt(Instant.now());
        entity.setAccessExpiredAt(Instant.now().plus(15, ChronoUnit.MINUTES));
        entity.setRefreshExpiredAt(Instant.now().plus(7, ChronoUnit.DAYS));
        entity.setRoles(rolesString);

        jwtRepository.save(entity);

        return new Token(opaqueAccess, opaqueRefresh);
    }

    @Override
    public Token refreshToken(RefreshToken refreshToken) {
        if (
            refreshToken == null ||
            refreshToken.refreshToken() == null ||
            refreshToken.refreshToken().isBlank()
        ) {
            throw new IllegalArgumentException("Invalid Token");
        }

        Optional<JwtEntity> optionalOldEntity =
            jwtRepository.findByRefreshToken(refreshToken.refreshToken());

        if (optionalOldEntity.isEmpty()) {
            throw new IllegalStateException("Invalid Refresh Token");
        }

        JwtEntity oldEntity = optionalOldEntity.get();

        if (oldEntity.getRefreshExpiredAt().isBefore(Instant.now())) {
            jwtRepository.delete(oldEntity);
            throw new IllegalStateException(
                "Refresh Token Expired. Please login again."
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
    public String introspectToJwt(AccessToken accessToken) {
        if (
            accessToken == null ||
            accessToken.accessToken() == null ||
            accessToken.accessToken().isBlank()
        ) {
            throw new IllegalArgumentException("Token not provided");
        }

        Optional<JwtEntity> optionalEntity = jwtRepository.findByAccessToken(
            accessToken.accessToken()
        );

        if (optionalEntity.isEmpty()) {
            throw new IllegalStateException("Token not found or invalid");
        }

        JwtEntity entity = optionalEntity.get();
        if (entity.getAccessExpiredAt().isBefore(Instant.now())) {
            throw new IllegalStateException("Access Token Expired");
        }

        return this.generateJwt(entity.getUserId(), entity.getRoles());
    }

    @Override
    public void revokeToken(RefreshToken refreshToken) {
        if (
            refreshToken == null ||
            refreshToken.refreshToken() == null ||
            refreshToken.refreshToken().isBlank()
        ) {
            throw new IllegalArgumentException("Token not provided");
        }

        Optional<JwtEntity> optionalEntity = jwtRepository.findByRefreshToken(
            refreshToken.refreshToken()
        );

        if (optionalEntity.isEmpty()) {
            throw new IllegalStateException("Token invalid or not found");
        }

        jwtRepository.delete(optionalEntity.get());
    }

    @Override
    public JWKSet getPublic() {
        return jwkSet;
    }
}

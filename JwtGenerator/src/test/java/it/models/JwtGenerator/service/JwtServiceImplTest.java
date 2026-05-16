package it.models.JwtGenerator.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.JWKSet;
import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import it.models.JwtGenerator.entity.JwtEntity;
import it.models.JwtGenerator.repository.JwtRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;

@ExtendWith(MockitoExtension.class)
class JwtServiceImplTest {

    @Mock
    private JwtRepository jwtRepository;

    @Mock
    private JWKSet jwkSet;

    @Mock
    private JwtEncoder encoder;

    @Captor
    private ArgumentCaptor<JwtEntity> entityCaptor;

    @InjectMocks
    private JwtServiceImpl service;

    @Test
    @DisplayName("Generate Token - Success for User Role")
    void generateToken_UserRole_Success() {
        UserProfile request = new UserProfile(
            "test@gmail.com",
            "Test",
            List.of("USER")
        );
        Token token = service.generateToken(request);

        verify(jwtRepository).save(entityCaptor.capture());
        JwtEntity savedEntity = entityCaptor.getValue();

        assertNotNull(token);
        assertNotNull(savedEntity.getAccessToken());
        assertNotNull(savedEntity.getRefreshToken());
    }

    @Test
    @DisplayName("Generate Token - Success for Admin Role")
    void generateToken_AdminRole_Success() {
        UserProfile request = new UserProfile(
            "admin@gmail.com",
            "Admin",
            List.of("ADMIN")
        );
        Token token = service.generateToken(request);

        verify(jwtRepository).save(entityCaptor.capture());
        JwtEntity savedEntity = entityCaptor.getValue();

        assertNotNull(token);
        assertNotNull(savedEntity.getAccessToken());
        assertNotNull(savedEntity.getRefreshToken());
    }

    @Test
    @DisplayName("Generate Token - Fails when Roles are null")
    void generateToken_NullRoles_ThrowsException() {
        UserProfile request = new UserProfile("test@gmail.com", "Test", null);
        assertThrows(IllegalArgumentException.class, () ->
            service.generateToken(request)
        );
        verify(jwtRepository, never()).save(any());
    }

    @Test
    @DisplayName("Generate Token - Fails when UserProfile is null")
    void generateToken_NullProfile_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () ->
            service.generateToken(null)
        );
        verify(jwtRepository, never()).save(any());
    }

    @Test
    @DisplayName("Refresh Token - Success")
    void refreshToken_Success() {
        Token tokenInput = new Token("oldAccessToken", "validRefreshToken");
        JwtEntity entity = new JwtEntity();
        entity.setAccessToken(tokenInput.accessToken());
        entity.setRefreshToken(tokenInput.refreshToken());
        entity.setEmittedAt(Instant.now());
        entity.setAccessExpiredAt(Instant.now().minusSeconds(10));
        entity.setRefreshExpiredAt(Instant.now().plusSeconds(600));

        when(jwtRepository.findByRefreshToken("validRefreshToken")).thenReturn(
            Optional.of(entity)
        );

        Token output = service.refreshToken(tokenInput);

        verify(jwtRepository).save(entityCaptor.capture());
        JwtEntity savedEntity = entityCaptor.getValue();

        assertNotNull(output);
        assertNotNull(savedEntity.getAccessToken());
        assertNotNull(savedEntity.getRefreshToken());
    }

    @Test
    @DisplayName("Refresh Token - Fails when Token is invalid or empty")
    void refreshToken_InvalidToken_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () ->
            service.refreshToken(null)
        );
        assertThrows(IllegalArgumentException.class, () ->
            service.refreshToken(new Token(null, "valid"))
        );
        assertThrows(IllegalArgumentException.class, () ->
            service.refreshToken(new Token("valid", ""))
        );
        verify(jwtRepository, never()).save(any());
    }

    @Test
    @DisplayName("Refresh Token - Fails when Refresh Token is not found")
    void refreshToken_NotFound_ThrowsException() {
        Token tokenInput = new Token("oldAccessToken", "unknownRefreshToken");
        when(
            jwtRepository.findByRefreshToken("unknownRefreshToken")
        ).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () ->
            service.refreshToken(tokenInput)
        );
        verify(jwtRepository, never()).save(any());
    }

    @Test
    @DisplayName("Refresh Token - Fails when Refresh Token is expired")
    void refreshToken_Expired_ThrowsException() {
        Token tokenInput = new Token("oldAccessToken", "expiredRefreshToken");
        JwtEntity entity = new JwtEntity();
        entity.setRefreshExpiredAt(Instant.now().minusSeconds(5));

        when(
            jwtRepository.findByRefreshToken("expiredRefreshToken")
        ).thenReturn(Optional.of(entity));

        assertThrows(IllegalStateException.class, () ->
            service.refreshToken(tokenInput)
        );
        verify(jwtRepository).delete(entity);
    }

    @Test
    @DisplayName("Refresh Token - Fails on Access Token mismatch")
    void refreshToken_AccessMismatch_ThrowsException() {
        Token tokenInput = new Token(
            "providedAccessToken",
            "validRefreshToken"
        );
        JwtEntity entity = new JwtEntity();
        entity.setAccessToken("differentAccessToken");
        entity.setRefreshExpiredAt(Instant.now().plusSeconds(600));

        when(jwtRepository.findByRefreshToken("validRefreshToken")).thenReturn(
            Optional.of(entity)
        );

        assertThrows(IllegalArgumentException.class, () ->
            service.refreshToken(tokenInput)
        );
        verify(jwtRepository).delete(entity);
    }

    @Test
    @DisplayName("Introspect to JWT - Success")
    void introspectToJwt_Success() {
        JwtEntity entity = new JwtEntity();
        entity.setId(100L);
        entity.setAccessExpiredAt(Instant.now().plusSeconds(60));

        when(jwtRepository.findByAccessToken("validAccess")).thenReturn(
            Optional.of(entity)
        );

        Jwt mockJwt = mock(Jwt.class);
        when(mockJwt.getTokenValue()).thenReturn("header.payload.signature");
        when(encoder.encode(any())).thenReturn(mockJwt);

        String output = service.introspectToJwt("validAccess");

        assertEquals("header.payload.signature", output);
    }

    @Test
    @DisplayName("Introspect to JWT - Fails when Token not found")
    void introspectToJwt_NotFound_ThrowsException() {
        when(jwtRepository.findByAccessToken("unknownAccess")).thenReturn(
            Optional.empty()
        );
        assertThrows(IllegalArgumentException.class, () ->
            service.introspectToJwt("unknownAccess")
        );
    }

    @Test
    @DisplayName("Introspect to JWT - Fails when Token is expired")
    void introspectToJwt_Expired_ThrowsException() {
        JwtEntity entity = new JwtEntity();
        entity.setAccessExpiredAt(Instant.now().minusSeconds(60));

        when(jwtRepository.findByAccessToken("expiredAccess")).thenReturn(
            Optional.of(entity)
        );

        assertThrows(IllegalStateException.class, () ->
            service.introspectToJwt("expiredAccess")
        );
    }

    @Test
    @DisplayName("Revoke Token - Success")
    void revokeToken_Success() {
        JwtEntity entity = new JwtEntity();
        when(jwtRepository.findByRefreshToken("validRefresh")).thenReturn(
            Optional.of(entity)
        );

        service.revokeToken("validRefresh");
        verify(jwtRepository).delete(entity);
    }

    @Test
    @DisplayName("Revoke Token - Fails when Token is null")
    void revokeToken_Null_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () ->
            service.revokeToken(null)
        );
        verify(jwtRepository, never()).delete(any());
    }

    @Test
    @DisplayName("Revoke Token - Fails when Token not found")
    void revokeToken_NotFound_ThrowsException() {
        when(jwtRepository.findByRefreshToken("unknownRefresh")).thenReturn(
            Optional.empty()
        );
        assertThrows(IllegalArgumentException.class, () ->
            service.revokeToken("unknownRefresh")
        );
        verify(jwtRepository, never()).delete(any());
    }
}

package it.models.JwtGenerator.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.jwk.JWKSet;
import it.models.JwtGenerator.dto.*;
import it.models.JwtGenerator.entity.JwtEntity;
import it.models.JwtGenerator.repository.JwtRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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

    @Nested
    @DisplayName("Generate Token Tests")
    class GenerateTokenTests {

        @Test
        void success() {
            UserProfile request = new UserProfile(1L, List.of("USER"));
            Token token = service.generateToken(request);
            verify(jwtRepository, times(1)).save(any());
            assertThat(token).isNotNull();
        }

        @Test
        void failsWhenRolesNull() {
            assertThatThrownBy(() ->
                service.generateToken(new UserProfile(1L, null))
            ).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void failsWhenProfileNull() {
            assertThatThrownBy(() -> service.generateToken(null)).isInstanceOf(
                IllegalArgumentException.class
            );
        }
    }

    @Nested
    @DisplayName("Refresh Token Tests")
    class RefreshTokenTests {

        @Test
        void success() {
            RefreshToken input = new RefreshToken("valid");
            JwtEntity entity = new JwtEntity();
            entity.setUserId(1L);
            entity.setAccessToken("old");
            entity.setRefreshToken("valid");
            entity.setEmittedAt(Instant.now());
            entity.setAccessExpiredAt(Instant.now().plusSeconds(60));
            entity.setRefreshExpiredAt(Instant.now().plusSeconds(600));
            entity.setRoles("ROLE_USER");
            when(jwtRepository.findByRefreshToken("valid")).thenReturn(
                Optional.of(entity)
            );

            Token output = service.refreshToken(input);
            assertThat(output).isNotNull();
        }

        @Test
        void failsWhenInvalid() {
            assertThatThrownBy(() ->
                service.refreshToken(new RefreshToken(null))
            ).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void failsWhenNotFound() {
            when(jwtRepository.findByRefreshToken("unknown")).thenReturn(
                Optional.empty()
            );
            assertThatThrownBy(() ->
                service.refreshToken(new RefreshToken("unknown"))
            ).isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    @DisplayName("Introspect Tests")
    class IntrospectTests {

        @Test
        void success() {
            JwtEntity entity = new JwtEntity();
            entity.setUserId(1L);
            entity.setRoles("ROLE_USER");
            entity.setAccessExpiredAt(Instant.now().plusSeconds(60));
            when(jwtRepository.findByAccessToken("valid")).thenReturn(
                Optional.of(entity)
            );

            Jwt mockJwt = mock(Jwt.class);
            when(mockJwt.getTokenValue()).thenReturn("token");
            when(encoder.encode(any())).thenReturn(mockJwt);

            assertThat(
                service.introspectToJwt(new AccessToken("valid"))
            ).isEqualTo("token");
        }

        @Test
        void failsWhenNotFound() {
            when(jwtRepository.findByAccessToken("bad")).thenReturn(
                Optional.empty()
            );
            assertThatThrownBy(() ->
                service.introspectToJwt(new AccessToken("bad"))
            ).isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    @DisplayName("Revoke Token Tests")
    class RevokeTokenTests {

        @Test
        void success() {
            JwtEntity entity = new JwtEntity();
            when(jwtRepository.findByRefreshToken("valid")).thenReturn(
                Optional.of(entity)
            );
            service.revokeToken(new RefreshToken("valid"));
            verify(jwtRepository).delete(any());
        }

        @Test
        void failsWhenNotFound() {
            when(jwtRepository.findByRefreshToken("bad")).thenReturn(
                Optional.empty()
            );
            assertThatThrownBy(() ->
                service.revokeToken(new RefreshToken("bad"))
            ).isInstanceOf(IllegalStateException.class);
        }
    }
}

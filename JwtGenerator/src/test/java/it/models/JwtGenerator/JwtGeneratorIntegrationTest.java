package it.models.JwtGenerator;

import static org.assertj.core.api.Assertions.assertThat;

import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtGeneratorIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
        "postgres:latest"
    );

    @LocalServerPort
    private int port;

    private TestRestTemplate restTemplate;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        this.restTemplate = new TestRestTemplate();
        this.baseUrl = "http://localhost:" + port + "/api/jwt";
    }

    private Token generateValidTokenForSetup() {
        UserProfile profile = new UserProfile(96L, List.of("USER"));
        ResponseEntity<Token> response = restTemplate.postForEntity(
            baseUrl + "/generate",
            profile,
            Token.class
        );
        return response.getBody();
    }

    @Test
    @DisplayName("E2E - Full flow: Generate, Introspect, Refresh and Logout")
    void fullJwtLifecycleFlow() {
        // 1. GENERATE
        UserProfile profile = new UserProfile(1L, List.of("ADMIN"));
        ResponseEntity<Token> genResp = restTemplate.postForEntity(
            baseUrl + "/generate",
            profile,
            Token.class
        );
        assertThat(genResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        Token generatedToken = genResp.getBody();
        assertThat(generatedToken).isNotNull();

        // 2. INTROSPECT
        ResponseEntity<String> introResp = restTemplate.postForEntity(
            baseUrl + "/introspect",
            generatedToken,
            String.class
        );
        assertThat(introResp.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 3. REFRESH
        ResponseEntity<Token> refResp = restTemplate.postForEntity(
            baseUrl + "/refresh",
            generatedToken,
            Token.class
        );
        assertThat(refResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        Token refreshedToken = refResp.getBody();
        assertThat(refreshedToken.accessToken()).isNotEqualTo(
            generatedToken.accessToken()
        );

        // 4. LOGOUT
        ResponseEntity<Void> logoutResp = restTemplate.postForEntity(
            baseUrl + "/logout",
            refreshedToken,
            Void.class
        );
        assertThat(logoutResp.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Nested
    @DisplayName("Tests for /api/jwt/generate")
    class GenerateTests {

        @Test
        @DisplayName(
            "Unhappy Path - Fails if user_id is missing (Validation Error)"
        )
        void shouldFailWhenRequiredFieldUserIdIsMissing() {
            UserProfile invalidProfile = new UserProfile(null, List.of("USER"));
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/generate",
                invalidProfile,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName(
            "Unhappy Path - Fails if roles field is null (Validation Error)"
        )
        void shouldFailWhenRequiredFieldRolesIsNull() {
            UserProfile invalidProfile = new UserProfile(1L, null);
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/generate",
                invalidProfile,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName(
            "Unhappy Path - Fails if roles list is empty (Validation Error)"
        )
        void shouldFailWhenRolesListIsEmpty() {
            UserProfile invalidProfile = new UserProfile(1L, List.of());
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/generate",
                invalidProfile,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName(
            "Unhappy Path - Fails if all required fields are missing (Validation Error)"
        )
        void shouldFailWhenAllRequiredFieldsAreMissing() {
            UserProfile invalidProfile = new UserProfile(null, null);
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/generate",
                invalidProfile,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }
    }

    @Nested
    @DisplayName("Tests for /api/jwt/introspect")
    class IntrospectTests {

        @Test
        @DisplayName(
            "Unhappy Path - Fails if Opaque Token does not exist in database"
        )
        void shouldFailWhenOpaqueTokenDoesNotExist() {
            Token unknownToken = new Token(
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff"
            );
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/introspect",
                unknownToken,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails if token is syntactically invalid")
        void shouldFailWhenTokenIsMalformedString() {
            Token malformedToken = new Token(
                "not-an-uuid-string",
                "not-an-uuid-refresh"
            );
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/introspect",
                malformedToken,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails if request body is missing")
        void shouldFailWhenIntrospectPayloadIsMissing() {
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/introspect",
                null,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }
    }

    @Nested
    @DisplayName("Tests for /api/jwt/refresh")
    class RefreshTests {

        @Test
        @DisplayName(
            "Unhappy Path - Fails if all fields are missing in payload"
        )
        void shouldFailWhenAllFieldsAreMissing() {
            Token invalidToken = new Token(null, null);
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/refresh",
                invalidToken,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails if request body is empty")
        void shouldFailWhenRefreshPayloadIsMissing() {
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/refresh",
                null,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails with non-existent Refresh Token")
        void shouldFailWithInvalidRefreshToken() {
            Token fakeToken = new Token(
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff"
            );
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/refresh",
                fakeToken,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }

        @Test
        @DisplayName(
            "Unhappy Path - Fails if access token used as refresh token"
        )
        void shouldFailIfAccessTokenIsUsedAsRefresh() {
            Token validToken = generateValidTokenForSetup();
            Token swappedToken = new Token(
                validToken.refreshToken(),
                validToken.accessToken()
            );
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/refresh",
                swappedToken,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails if token strings are malformed")
        void shouldFailWhenRefreshTokensAreMalformed() {
            Token malformedToken = new Token(
                "not-an-uuid-access",
                "not-an-uuid-refresh"
            );
            ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/refresh",
                malformedToken,
                String.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }
    }

    @Nested
    @DisplayName("Tests for /api/jwt/logout")
    class LogoutTests {

        @Test
        @DisplayName(
            "Unhappy Path - Fails if all fields are missing in payload"
        )
        void shouldFailWhenAllFieldsAreMissing() {
            Token invalidToken = new Token(null, null);
            ResponseEntity<Void> response = restTemplate.postForEntity(
                baseUrl + "/logout",
                invalidToken,
                Void.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails if request body is missing")
        void shouldFailWhenLogoutPayloadIsMissing() {
            ResponseEntity<Void> response = restTemplate.postForEntity(
                baseUrl + "/logout",
                null,
                Void.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.BAD_REQUEST
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails with already revoked token")
        void shouldFailWithAlreadyLoggedOutToken() {
            Token validToken = generateValidTokenForSetup();
            restTemplate.postForEntity(
                baseUrl + "/logout",
                validToken,
                Void.class
            );
            ResponseEntity<Void> secondLogoutResp = restTemplate.postForEntity(
                baseUrl + "/logout",
                validToken,
                Void.class
            );
            assertThat(secondLogoutResp.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }

        @Test
        @DisplayName("Unhappy Path - Fails if Opaque Token does not exist")
        void shouldFailWhenLogoutTokenDoesNotExist() {
            Token unknownToken = new Token(
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff"
            );
            ResponseEntity<Void> response = restTemplate.postForEntity(
                baseUrl + "/logout",
                unknownToken,
                Void.class
            );
            assertThat(response.getStatusCode()).isEqualTo(
                HttpStatus.UNAUTHORIZED
            );
        }
    }
}

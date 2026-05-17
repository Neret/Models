package it.models.JwtGenerator.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import it.models.JwtGenerator.service.JwtService;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import tools.jackson.databind.ObjectMapper;

@WebMvcTest(JwtGeneratorControllerImpl.class)
@AutoConfigureMockMvc(addFilters = false)
class JwtGeneratorControllerImplTest {

    @MockitoBean
    private JwtService jwtService;

    @Autowired
    private MockMvcTester mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /generate - Success")
    void generateToken_Success() throws Exception {
        Token token = new Token("opaqueAccess123", "opaqueRefresh456");
        UserProfile request = new UserProfile(1L, List.of("USER"));

        when(jwtService.generateToken(request)).thenReturn(token);

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        ).hasStatusOk();
    }

    @Test
    @DisplayName(
        "POST /generate - Bad Request on invalid fields (Validation Failure)"
    )
    void generateToken_InvalidFields_BadRequest() throws Exception {
        UserProfile request = new UserProfile(null, List.of());

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        ).hasStatus(400);
    }

    @Test
    @DisplayName("POST /refresh - Success")
    void refreshToken_Success() throws Exception {
        Token tokenRequest = new Token("OLDopaqueAccess", "OLDopaqueRefresh");
        Token tokenResponse = new Token("NEWopaqueAccess", "NEWopaqueRefresh");

        when(jwtService.refreshToken(tokenRequest)).thenReturn(tokenResponse);

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tokenRequest))
        ).hasStatusOk();
    }

    @Test
    @DisplayName(
        "POST /refresh - Bad Request on blank tokens (Validation Failure)"
    )
    void refreshToken_BlankTokens_BadRequest() throws Exception {
        Token tokenRequest = new Token("", "   ");

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tokenRequest))
        ).hasStatus(400);
    }

    @Test
    @DisplayName("GET /jwks - Success")
    void jwks_Success() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.genKeyPair();
        JWK jwk = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
            .privateKey((RSAPrivateKey) pair.getPrivate())
            .build();
        JWKSet jwkset = new JWKSet(jwk);

        when(jwtService.getPublic()).thenReturn(jwkset);

        assertThat(
            mockMvc
                .get()
                .uri("/api/jwt/jwks")
                .accept(MediaType.APPLICATION_JSON)
        ).hasStatusOk();
    }

    @Test
    @DisplayName("POST /logout - Success")
    void logout_Success() throws Exception {
        Token tokenRequest = new Token("validAccessToken", "validRefreshToken");
        Mockito.doNothing().when(jwtService).revokeToken(tokenRequest);

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tokenRequest))
        ).hasStatusOk();
    }

    @Test
    @DisplayName(
        "POST /logout - Bad Request on blank param (Validation Failure)"
    )
    void logout_BlankParam_BadRequest() throws Exception {
        Token tokenRequest = new Token("validAccessToken", "   ");

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tokenRequest))
        ).hasStatus(400);
    }

    @Test
    @DisplayName("POST /introspect - Success")
    void introspect_Success() throws Exception {
        Token tokenRequest = new Token("opaqueAccess123", "opaqueRefresh123");
        String jwtOutput = "header.payload.signature";

        when(jwtService.introspectToJwt(tokenRequest)).thenReturn(jwtOutput);

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/introspect")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tokenRequest))
        ).hasStatusOk();
    }

    @Test
    @DisplayName(
        "POST /introspect - Bad Request on blank param (Validation Failure)"
    )
    void introspect_BlankParam_BadRequest() throws Exception {
        Token tokenRequest = new Token("", "opaqueRefresh123");

        assertThat(
            mockMvc
                .post()
                .uri("/api/jwt/introspect")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tokenRequest))
        ).hasStatus(400);
    }
}

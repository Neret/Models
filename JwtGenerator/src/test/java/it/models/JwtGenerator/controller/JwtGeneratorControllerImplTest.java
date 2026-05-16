package it.models.JwtGenerator.controller;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestConstructor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

@WebMvcTest(JwtGeneratorControllerImpl.class)
@AutoConfigureMockMvc(addFilters = false)
@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
class JwtGeneratorControllerImplTest {

    @MockitoBean
    private JwtService jwtService;

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;

    public JwtGeneratorControllerImplTest(
        MockMvc mockMvc,
        ObjectMapper objectMapper
    ) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
    }

    @Test
    @DisplayName("POST /generate - Success")
    void generateToken_Success() throws Exception {
        Token token = new Token("opaqueAccess123", "opaqueRefresh456");
        UserProfile request = new UserProfile(
            "test@gmail.com",
            "Test",
            List.of("USER")
        );

        when(
            jwtService.generateToken(Mockito.any(UserProfile.class))
        ).thenReturn(token);

        mockMvc
            .perform(
                post("/api/jwt/generate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request))
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /generate - Bad Request on missing body")
    void generateToken_MissingBody_BadRequest() throws Exception {
        mockMvc
            .perform(
                post("/api/jwt/generate").contentType(
                    MediaType.APPLICATION_JSON
                )
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /refresh - Success")
    void refreshToken_Success() throws Exception {
        Token tokenRequest = new Token("OLDopaqueAccess", "OLDopaqueRefresh");
        Token tokenResponse = new Token("NEWopaqueAccess", "NEWopaqueRefresh");

        when(jwtService.refreshToken(Mockito.any(Token.class))).thenReturn(
            tokenResponse
        );

        mockMvc
            .perform(
                post("/api/jwt/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(tokenRequest))
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /refresh - Bad Request on empty body")
    void refreshToken_EmptyBody_BadRequest() throws Exception {
        mockMvc
            .perform(
                post("/api/jwt/refresh").contentType(MediaType.APPLICATION_JSON)
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /refresh - Service throws IllegalArgumentException")
    void refreshToken_InvalidToken_BadRequest() throws Exception {
        Token tokenRequest = new Token(null, "OLDopaqueRefresh");

        when(jwtService.refreshToken(Mockito.any(Token.class))).thenThrow(
            new IllegalArgumentException("Invalid Token")
        );

        mockMvc
            .perform(
                post("/api/jwt/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(tokenRequest))
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("GET /jwks - Success")
    void jwks_Success() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = generator.genKeyPair();
        JWK jwk = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
            .privateKey((RSAPrivateKey) pair.getPrivate())
            .build();
        JWKSet jwkset = new JWKSet(jwk);

        when(jwtService.getPublic()).thenReturn(jwkset);

        mockMvc
            .perform(
                get("/api/jwt/jwks").contentType(MediaType.APPLICATION_JSON)
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /logout - Success")
    void logout_Success() throws Exception {
        Mockito.doNothing().when(jwtService).revokeToken(Mockito.anyString());

        mockMvc
            .perform(
                post("/api/jwt/logout")
                    .param("refreshToken", "refresh_token_123")
                    .contentType(MediaType.APPLICATION_JSON)
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /logout - Bad Request on missing param")
    void logout_MissingParam_BadRequest() throws Exception {
        mockMvc
            .perform(
                post("/api/jwt/logout").contentType(MediaType.APPLICATION_JSON)
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /introspect - Success")
    void introspect_Success() throws Exception {
        String tokenInput = "opaqueAccess123";
        String jwtOutput = "header.payload.signature";

        when(jwtService.introspectToJwt(Mockito.anyString())).thenReturn(
            jwtOutput
        );

        mockMvc
            .perform(
                post("/api/jwt/introspect")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(tokenInput)
            )
            .andExpect(status().isOk());
    }
}

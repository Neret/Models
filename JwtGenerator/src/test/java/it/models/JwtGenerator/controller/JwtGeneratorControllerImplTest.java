package it.models.JwtGenerator.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import it.models.JwtGenerator.dto.*;
import it.models.JwtGenerator.service.JwtService;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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

    @Nested
    @DisplayName("POST /api/jwt/generate")
    class GenerateTests {

        @Test
        void success() throws Exception {
            UserProfile request = new UserProfile(1L, List.of("USER"));
            when(jwtService.generateToken(request)).thenReturn(
                new Token("a", "r")
            );
            assertThat(
                mockMvc
                    .post()
                    .uri("/api/jwt/generate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request))
            ).hasStatusOk();
        }

        @Test
        void badRequest() throws Exception {
            assertThat(
                mockMvc
                    .post()
                    .uri("/api/jwt/generate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{}")
            ).hasStatus(400);
        }
    }

    @Nested
    @DisplayName("POST /api/jwt/refresh")
    class RefreshTests {

        @Test
        void success() throws Exception {
            RefreshToken req = new RefreshToken("old");
            when(jwtService.refreshToken(req)).thenReturn(
                new Token("newA", "newR")
            );
            assertThat(
                mockMvc
                    .post()
                    .uri("/api/jwt/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(req))
            ).hasStatusOk();
        }
    }

    @Nested
    @DisplayName("POST /api/jwt/introspect")
    class IntrospectTests {

        @Test
        void success() throws Exception {
            AccessToken req = new AccessToken("a");
            when(jwtService.introspectToJwt(req)).thenReturn("jwt");
            assertThat(
                mockMvc
                    .post()
                    .uri("/api/jwt/introspect")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(req))
            ).hasStatusOk();
        }
    }

    @Nested
    @DisplayName("POST /api/jwt/logout")
    class LogoutTests {

        @Test
        void success() throws Exception {
            RefreshToken req = new RefreshToken("r");
            assertThat(
                mockMvc
                    .post()
                    .uri("/api/jwt/logout")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(req))
            ).hasStatusOk();
        }
    }
}

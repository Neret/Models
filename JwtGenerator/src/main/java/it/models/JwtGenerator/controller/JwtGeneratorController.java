package it.models.JwtGenerator.controller;

import it.models.JwtGenerator.dto.*;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public interface JwtGeneratorController {
    ResponseEntity<Token> generateToken(@Valid UserProfile userProfile);
    ResponseEntity<Token> refreshToken(@Valid RefreshToken refreshToken);
    ResponseEntity<String> introspect(@Valid AccessToken accessToken);
    ResponseEntity<Map<String, Object>> jwks();
    ResponseEntity<Void> logout(@Valid RefreshToken refreshToken);
}

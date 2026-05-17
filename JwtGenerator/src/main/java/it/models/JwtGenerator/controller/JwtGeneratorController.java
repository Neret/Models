package it.models.JwtGenerator.controller;

import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public interface JwtGeneratorController {
    ResponseEntity<Token> generateToken(@Valid UserProfile userProfile);
    ResponseEntity<Token> refreshToken(@Valid Token token);
    ResponseEntity<String> introspect(@Valid Token token);
    ResponseEntity<Map<String, Object>> jwks();
    ResponseEntity<Void> logout(@Valid Token token);
}

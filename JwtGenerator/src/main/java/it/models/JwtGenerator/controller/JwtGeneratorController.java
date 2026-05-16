package it.models.JwtGenerator.controller;

import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public interface JwtGeneratorController {
    ResponseEntity<Token> generateToken(UserProfile jsonRequest);
    ResponseEntity<Token> refreshToken(Token token);
    ResponseEntity<String> introspect(String accessToken);
    ResponseEntity<Map<String, Object>> jwks();
    ResponseEntity<Void> logout(String refreshToken);
}

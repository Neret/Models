package it.models.JwtGenerator.controller;

import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import it.models.JwtGenerator.service.JwtService;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/jwt")
public class JwtGeneratorControllerImpl implements JwtGeneratorController {

    private final JwtService jwtService;

    public JwtGeneratorControllerImpl(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/generate")
    @Override
    public ResponseEntity<Token> generateToken(
        @RequestBody UserProfile jsonRequest
    ) {
        return ResponseEntity.ok(jwtService.generateToken(jsonRequest));
    }

    @PostMapping("/refresh")
    @Override
    public ResponseEntity<Token> refreshToken(@RequestBody Token token) {
        return ResponseEntity.ok(jwtService.refreshToken(token));
    }

    @GetMapping("/jwks")
    @Override
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok(jwtService.getPublic().toJSONObject());
    }

    @PostMapping("/logout")
    @Override
    public ResponseEntity<Void> logout(@RequestParam String refreshToken) {
        jwtService.revokeToken(refreshToken);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/introspect")
    @Override
    public ResponseEntity<String> introspect(@RequestBody String accessToken) {
        return ResponseEntity.ok(jwtService.introspectToJwt(accessToken));
    }
}

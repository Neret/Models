package it.models.auth_service.controller;

import it.models.auth_service.dto.*;
import it.models.auth_service.service.AuthService;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/google-login")
    public ResponseEntity<AuthResponse> loginWithGoogle(
        @RequestBody GoogleLoginRequest request
    ) {
        return ResponseEntity.ok(
            authService.loginWithGoogle(request.idToken())
        );
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
        @RequestBody LocalRegisterRequest request
    ) {
        authService.registerLocalUser(
            request.email(),
            request.password(),
            request.nome(),
            request.cognome()
        );
        return ResponseEntity.ok("Registrazione completata.");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
        @RequestBody LocalLoginRequest request
    ) {
        return ResponseEntity.ok(
            authService.loginLocal(request.email(), request.password())
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
        @RequestBody RefreshRequest request
    ) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @GetMapping("/get-public-key")
    public ResponseEntity<Map<String, Object>> getJwkSet() {
        return ResponseEntity.ok(authService.getPublicKey());
    }

    @PostMapping("/password-reset/request")
    public ResponseEntity<Void> requestReset(
        @RequestBody Map<String, String> body
    ) {
        authService.requestPasswordReset(body.get("email"));
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Void> confirmReset(
        @RequestBody Map<String, String> body
    ) {
        authService.completePasswordReset(
            body.get("token"),
            body.get("newPassword")
        );
        return ResponseEntity.ok().build();
    }

    @PostMapping("/mfa/setup")
    public ResponseEntity<MfaSetupResponse> setupMfa(
        @RequestBody Map<String, String> body
    ) {
        return ResponseEntity.ok(authService.setupMfa(body.get("email")));
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<AuthResponse> verifyMfa(
        @RequestBody Map<String, String> body
    ) {
        return ResponseEntity.ok(
            authService.verifyMfaAndLogin(body.get("email"), body.get("code"))
        );
    }
}

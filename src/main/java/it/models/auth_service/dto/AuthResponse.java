package it.models.auth_service.dto;

public record AuthResponse(
    String accessToken,
    String refreshToken,
    boolean mfaRequired
) {}

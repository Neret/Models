package it.models.JwtGenerator.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshToken(
    @NotBlank(message = "Refresh token cannot be null or blank")
    String refreshToken
) {}

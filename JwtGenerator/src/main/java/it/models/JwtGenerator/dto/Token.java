package it.models.JwtGenerator.dto;

import jakarta.validation.constraints.NotBlank;

public record Token(
    @NotBlank(message = "Access token is required") String accessToken,

    @NotBlank(message = "Refresh token is required") String refreshToken
) {}

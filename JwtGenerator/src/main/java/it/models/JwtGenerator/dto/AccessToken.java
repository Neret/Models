package it.models.JwtGenerator.dto;

import jakarta.validation.constraints.NotBlank;

public record AccessToken(
    @NotBlank(message = "Access token cannot be null or blank")
    String accessToken
) {}

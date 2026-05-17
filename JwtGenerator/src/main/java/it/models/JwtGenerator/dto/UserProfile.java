package it.models.JwtGenerator.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record UserProfile(
    @NotNull(message = "User ID is required") Long id,

    @NotEmpty(message = "At least one role is required") List<String> roles
) {}

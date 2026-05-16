package it.models.JwtGenerator.dto;

import java.util.List;

public record UserProfile(String email, String firstName, List<String> roles) {}

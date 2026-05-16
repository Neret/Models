package it.models.JwtGenerator.dto;

import java.util.List;

public record UserProfile(long id, List<String> roles) {}

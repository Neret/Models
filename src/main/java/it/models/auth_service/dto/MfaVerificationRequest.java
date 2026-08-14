package it.models.auth_service.dto;

public record MfaVerificationRequest(String email, String code) {}

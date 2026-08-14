package it.models.auth_service.dto;

public record MfaSetupResponse(String secret, String qrCodeUri) {}

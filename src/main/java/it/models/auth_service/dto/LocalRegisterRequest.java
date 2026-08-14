package it.models.auth_service.dto;

public record LocalRegisterRequest(
    String email,
    String password,
    String nome,
    String cognome
) {}

package it.models.JwtGenerator.service;

import com.nimbusds.jose.jwk.JWKSet;
import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import org.springframework.stereotype.Service;

@Service
public interface JwtService {
    Token generateToken(UserProfile jsonRequest);
    Token refreshToken(Token token);
    JWKSet getPublic();
    String introspectToJwt(Token token);
    void revokeToken(Token token);
}

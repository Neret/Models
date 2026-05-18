package it.models.JwtGenerator.service;

import com.nimbusds.jose.jwk.JWKSet;
import it.models.JwtGenerator.dto.AccessToken;
import it.models.JwtGenerator.dto.RefreshToken;
import it.models.JwtGenerator.dto.Token;
import it.models.JwtGenerator.dto.UserProfile;
import org.springframework.stereotype.Service;

@Service
public interface JwtService {
    Token generateToken(UserProfile userProfile);
    Token refreshToken(RefreshToken refreshToken);
    JWKSet getPublic();
    String introspectToJwt(AccessToken accessToken);
    void revokeToken(RefreshToken refreshToken);
}

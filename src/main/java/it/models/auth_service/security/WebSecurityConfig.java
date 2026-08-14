package it.models.auth_service.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final GatewayFilter gatewayFilter;
    private final JwtDecoder jwtDecoder;

    public WebSecurityConfig(
        GatewayFilter gatewayFilter,
        @Qualifier("jwtDecoder") JwtDecoder jwtDecoder
    ) {
        this.gatewayFilter = gatewayFilter;
        this.jwtDecoder = jwtDecoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .addFilterBefore(
                gatewayFilter,
                UsernamePasswordAuthenticationFilter.class
            )
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth ->
                auth
                    .requestMatchers(
                        "/api/auth/google-login",
                        "/api/auth/refresh",
                        "/api/auth/get-public-key",
                        "/api/auth/register",
                        "/api/auth/login",
                        "/api/auth/password-reset/**",
                        "/api/auth/mfa/**"
                    )
                    .permitAll()
                    .anyRequest()
                    .authenticated()
            )
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt -> jwt.decoder(jwtDecoder))
            )
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public TextEncryptor textEncryptor() {
        return Encryptors.text("password-segreta", "5c0744940b5c369b");
    }
}

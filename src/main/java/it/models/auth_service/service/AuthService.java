package it.models.auth_service.service;

import com.nimbusds.jose.jwk.JWKSet;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import it.models.auth_service.dto.*;
import it.models.auth_service.entity.*;
import it.models.auth_service.repository.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(
        AuthService.class
    );

    private final JwtDecoder googleDecoder;
    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository rTokenRepository;
    private final JWKSet jwkSet;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;
    private final TextEncryptor textEncryptor;
    @Value("${app.frontend.url}")
    private String frontendUrl;

    public AuthService(
        @Qualifier("googleJwtDecoder") JwtDecoder googleDecoder,
        JwtEncoder jwtEncoder,
        UserRepository userRepository,
        RefreshTokenRepository rTokenRepository,
        JWKSet jwkSet,
        PasswordEncoder passwordEncoder,
        JavaMailSender mailSender,
        TextEncryptor textEncryptor
    ) {
        this.googleDecoder = googleDecoder;
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.rTokenRepository = rTokenRepository;
        this.jwkSet = jwkSet;
        this.passwordEncoder = passwordEncoder;
        this.mailSender = mailSender;
        this.textEncryptor = textEncryptor;
    }

    public AuthResponse loginLocal(String email, String rawPassword) {
        Optional<User> optionalUser = userRepository.findByUsername(email);

        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Credenziali non valide.");
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new RuntimeException("Credenziali non valide.");
        }

        if (user.isMfaEnabled()) {
            return new AuthResponse(null, null, true);
        }

        return generaTokens(user);
    }

    public AuthResponse loginWithGoogle(String token) {
        Jwt googleJwt = googleDecoder.decode(token);
        String email = googleJwt.getClaimAsString("email");

        Optional<User> optionalUser = userRepository.findByUsername(email);
        User user;

        if (optionalUser.isPresent()) {
            user = optionalUser.get();
            if ("LOCAL".equals(user.getProvider())) {
                throw new RuntimeException(
                    "Email registrata con password. Usa login locale."
                );
            }
        } else {
            user = new User();
            user.setUsername(email);
            user.setFirstName(googleJwt.getClaimAsString("given_name"));
            user.setLastName(googleJwt.getClaimAsString("family_name"));
            user.setProvider("GOOGLE");

            Role role = new Role();
            role.setRole("ROLE_USER");

            Set<Role> roles = new HashSet<Role>();
            roles.add(role);
            user.setRoles(roles);

            userRepository.save(user);
        }

        return generaTokens(user);
    }

    public void registerLocalUser(
        String email,
        String rawPassword,
        String nome,
        String cognome
    ) {
        Optional<User> existing = userRepository.findByUsername(email);
        if (existing.isPresent()) {
            throw new RuntimeException("Utente già esistente.");
        }

        User newUser = new User();
        newUser.setUsername(email);
        newUser.setFirstName(nome);
        newUser.setLastName(cognome);
        newUser.setProvider("LOCAL");
        newUser.setPassword(passwordEncoder.encode(rawPassword));

        Role role = new Role();
        role.setRole("ROLE_USER");

        Set<Role> roles = new HashSet<Role>();
        roles.add(role);
        newUser.setRoles(roles);

        userRepository.save(newUser);
    }

    public MfaSetupResponse setupMfa(String email) {
        Optional<User> optionalUser = userRepository.findByUsername(email);
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Utente non trovato");
        }

        User user = optionalUser.get();

        SecretGenerator generator = new DefaultSecretGenerator();
        String rawSecret = generator.generate();

        user.setMfaSecret(textEncryptor.encrypt(rawSecret));
        user.setMfaEnabled(true);
        userRepository.save(user);

        String issuer = "AuthService";
        String qrCodeUri = String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer, email, rawSecret, issuer
        );

        return new MfaSetupResponse(rawSecret, qrCodeUri);
    }

    public AuthResponse verifyMfaAndLogin(String email, String code) {
        Optional<User> optionalUser = userRepository.findByUsername(email);
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Utente non trovato");
        }

        User user = optionalUser.get();

        String rawSecret = textEncryptor.decrypt(user.getMfaSecret());
        CodeVerifier verifier = new DefaultCodeVerifier(
            new DefaultCodeGenerator(),
            new SystemTimeProvider()
        );

        if (verifier.isValidCode(rawSecret, code)) {
            return generaTokens(user);
        }
        throw new RuntimeException("Codice 2FA errato");
    }

    public void requestPasswordReset(String email) {
        Optional<User> optUser = userRepository.findByUsername(email);
        if (optUser.isPresent()) {
            User user = optUser.get();
            String token = UUID.randomUUID().toString();
            user.setResetToken(token);
            user.setResetTokenExpiry(
                    Instant.now().plus(15, ChronoUnit.MINUTES)
            );
            userRepository.save(user);

            String resetLink = frontendUrl + "/reset-password?token=" + token;

            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Richiesta Reset Password");
            message.setText(
                    "Ciao,\n\n" +
                            "Hai richiesto di reimpostare la password per il tuo account.\n" +
                            "Clicca sul link sottostante per procedere (il link è valido per 15 minuti):\n\n" +
                            resetLink + "\n\n" +
                            "Se non sei stato tu a richiederlo, ignora questa email."
            );

            mailSender.send(message);
            logger.info("Email di reset password inviata a " + email);
        }
    }

    public void completePasswordReset(String token, String newRawPassword) {
        Optional<User> optionalUser = userRepository.findByResetToken(token);
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Token non valido");
        }

        User user = optionalUser.get();

        if (Instant.now().isAfter(user.getResetTokenExpiry())) {
            throw new RuntimeException("Token scaduto");
        }

        user.setPassword(passwordEncoder.encode(newRawPassword));
        user.setResetToken(null);
        userRepository.save(user);
    }

    public AuthResponse refreshToken(RefreshRequest request) {
        Optional<RefreshToken> optionalRt = rTokenRepository.findByRefreshToken(
            request.refreshToken()
        );

        if (optionalRt.isEmpty()) {
            throw new RuntimeException("Token non trovato");
        }

        RefreshToken rt = optionalRt.get();

        if (Instant.now().isAfter(rt.getExpiredTime())) {
            rTokenRepository.delete(rt);
            throw new RuntimeException("Token scaduto");
        }

        return generaTokens(rt.getUser());
    }

    private AuthResponse generaTokens(User user) {
        String scope = "";
        Collection<? extends GrantedAuthority> authorities =
            user.getAuthorities();

        for (GrantedAuthority authority : authorities) {
            String roleName = authority.getAuthority();
            if (scope.isEmpty()) {
                scope = roleName;
            } else {
                scope = scope + " " + roleName;
            }
        }

        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("auth-service")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(600))
            .subject(user.getUsername())
            .claim("scope", scope)
            .claim("nome", user.getFirstName())
            .claim("cognome", user.getLastName())
            .build();

        String accessToken = jwtEncoder
            .encode(JwtEncoderParameters.from(claims))
            .getTokenValue();

        RefreshToken rt = new RefreshToken();
        rt.setRefreshToken(UUID.randomUUID().toString());
        rt.setExpiredTime(Instant.now().plus(30, ChronoUnit.DAYS));
        rt.setUser(user);
        rTokenRepository.save(rt);

        return new AuthResponse(accessToken, rt.getRefreshToken(), false);
    }

    public Map<String, Object> getPublicKey() {
        return this.jwkSet.toJSONObject();
    }
}

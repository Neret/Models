package it.models.auth_service.config;

import it.models.auth_service.entity.Role;
import it.models.auth_service.entity.User;
import it.models.auth_service.repository.UserRepository;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DatabaseInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(
        DatabaseInitializer.class
    );

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TextEncryptor encryptor;

    @Value("${app.admin.email}")
    private String adminEmail;

    @Value("${app.admin.password}")
    private String password;

    @Value("${app.admin.firstname}")
    private String firstname;

    @Value("${app.admin.lastname}")
    private String lastname;

    public DatabaseInitializer(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder,
        TextEncryptor encryptor
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.encryptor = encryptor;
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info(
            "Controllo esistenza utente ADMIN con email: " + adminEmail
        );

        Optional<User> optionalAdmin = userRepository.findByUsername(
            adminEmail
        );
        if (optionalAdmin.isEmpty()) {
            User superAdmin = new User();
            superAdmin.setUsername(adminEmail);
            superAdmin.setProvider("LOCAL");

            String hashedPassword = passwordEncoder.encode(password);
            superAdmin.setPassword(hashedPassword);

            superAdmin.setFirstName(encryptor.encrypt(firstname));
            superAdmin.setLastName(encryptor.encrypt(lastname));

            Role adminRole = new Role();
            adminRole.setRole("ROLE_ADMIN");

            Set<Role> roles = new HashSet<Role>();
            roles.add(adminRole);
            superAdmin.setRoles(roles);

            userRepository.save(superAdmin);

            logger.info("UTENTE ADMIN CREATO!");
            logger.info("Email: " + adminEmail);
        } else {
            logger.info("L'utente ADMIN esiste già nel database.");
        }
    }
}

package it.models.JwtGenerator.repository;

import static org.assertj.core.api.Assertions.assertThat;

import it.models.JwtGenerator.entity.JwtEntity;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@DataJpaTest
@Testcontainers
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class JwtRepositoryTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
        "postgres:latest"
    );

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private JwtRepository jwtRepository;

    @Test
    @DisplayName("Repository - Find by Access Token")
    void findByAccessToken_ReturnsEntity() {
        JwtEntity entity = new JwtEntity();
        entity.setUserId(888888L);
        entity.setAccessToken("opaque_access_555");
        entity.setRefreshToken("opaque_refresh_555");
        entity.setEmittedAt(Instant.now());
        entity.setAccessExpiredAt(Instant.now().plusSeconds(60));
        entity.setRefreshExpiredAt(Instant.now().plusSeconds(300));
        entity.setRoles("ROLE_USER");

        entityManager.persistAndFlush(entity);

        Optional<JwtEntity> found = jwtRepository.findByAccessToken(
            "opaque_access_555"
        );

        assertThat(found).isPresent();
        assertThat(found.get().getRefreshToken()).isEqualTo(
            "opaque_refresh_555"
        );
        assertThat(found.get().getUserId()).isEqualTo(888888L);
    }

    @Test
    @DisplayName("Repository - Find by Refresh Token")
    void findByRefreshToken_ReturnsEntity() {
        JwtEntity entity = new JwtEntity();
        entity.setUserId(888888L);
        entity.setAccessToken("opaque_access_555");
        entity.setRefreshToken("opaque_refresh_555");
        entity.setEmittedAt(Instant.now());
        entity.setAccessExpiredAt(Instant.now().plusSeconds(60));
        entity.setRefreshExpiredAt(Instant.now().plusSeconds(300));
        entity.setRoles("ROLE_USER");

        entityManager.persistAndFlush(entity);

        Optional<JwtEntity> found = jwtRepository.findByRefreshToken(
            "opaque_refresh_555"
        );

        assertThat(found).isPresent();
        assertThat(found.get().getAccessToken()).isEqualTo("opaque_access_555");
        assertThat(found.get().getUserId()).isEqualTo(888888L);
    }
}

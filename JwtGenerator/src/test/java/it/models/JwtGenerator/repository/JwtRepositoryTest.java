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
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;

@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
class JwtRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private JwtRepository jwtRepository;

    @Test
    @DisplayName("Repository - Find by Token")
    void findByAccessToken_ReturnsEntity() {
        JwtEntity entity = new JwtEntity();
        entity.setUserId(999999L);
        entity.setAccessToken("opaque_access_124");
        entity.setRefreshToken("opaque_refresh_124");
        entity.setEmittedAt(Instant.now());
        entity.setAccessExpiredAt(Instant.now().plusSeconds(60));
        entity.setRefreshExpiredAt(Instant.now().plusSeconds(300));
        entity.setRoles("ROLE_ADMIN");

        entityManager.persistAndFlush(entity);

        Optional<JwtEntity> found = jwtRepository.findByAccessTokenAndRefreshToken(
            "opaque_access_124",
            "opaque_refresh_124"
        );

        assertThat(found).isPresent();
        assertThat(found.get().getUserId()).isEqualTo(999999L);
    }
}

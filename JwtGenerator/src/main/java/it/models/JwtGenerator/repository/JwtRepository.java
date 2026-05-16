package it.models.JwtGenerator.repository;

import it.models.JwtGenerator.entity.JwtEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface JwtRepository extends JpaRepository<JwtEntity, Long> {
    Optional<JwtEntity> findByRefreshToken(String refresh);
    Optional<JwtEntity> findByAccessToken(String opaqueAccessToken);
}

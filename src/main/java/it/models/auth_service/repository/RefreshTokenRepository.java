package it.models.auth_service.repository;

import it.models.auth_service.entity.RefreshToken;
import it.models.auth_service.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository
    extends JpaRepository<RefreshToken, Long>
{
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
    int deleteByUser(User user);
}

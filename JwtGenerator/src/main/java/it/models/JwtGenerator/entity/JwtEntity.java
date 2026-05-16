package it.models.JwtGenerator.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "db_token")
public class JwtEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "access_token", nullable = false, unique = true)
    private String accessToken;

    @Column(name = "refresh_token", nullable = false, unique = true)
    private String refreshToken;

    @Column(name = "emitted_at", nullable = false)
    private Instant emittedAt;

    @Column(name = "access_expired_at", nullable = false)
    private Instant accessExpiredAt;

    @Column(name = "refresh_expired_at", nullable = false)
    private Instant refreshExpiredAt;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Instant getEmittedAt() {
        return emittedAt;
    }

    public void setEmittedAt(Instant emittedAt) {
        this.emittedAt = emittedAt;
    }

    public Instant getAccessExpiredAt() {
        return accessExpiredAt;
    }

    public void setAccessExpiredAt(Instant accessExpiredAt) {
        this.accessExpiredAt = accessExpiredAt;
    }

    public Instant getRefreshExpiredAt() {
        return refreshExpiredAt;
    }

    public void setRefreshExpiredAt(Instant refreshExpiredAt) {
        this.refreshExpiredAt = refreshExpiredAt;
    }
}

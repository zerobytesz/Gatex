package com.smartgateway.gateway.auth;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** User accounts stored in the app_users table (MySQL in Docker, H2 for local runs). */
@Repository
public class UserRepository {

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public Optional<UserAccount> find(String username) {
        List<UserAccount> rows = jdbc.query(
                "SELECT username, password_hash, role FROM app_users WHERE username = ?",
                (rs, i) -> new UserAccount(rs.getString(1), rs.getString(2), rs.getString(3)), username);
        return rows.stream().findFirst();
    }

    public boolean create(String username, String passwordHash, String role) {
        try {
            return jdbc.update("INSERT INTO app_users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    username, passwordHash, role, System.currentTimeMillis()) == 1;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    public long count() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM app_users", Long.class);
        return n == null ? 0 : n;
    }
}

-- Portable schema (MySQL 8 and H2 in MySQL mode). Times are epoch milliseconds.
CREATE TABLE IF NOT EXISTS app_users (
    username      VARCHAR(64)  NOT NULL PRIMARY KEY,
    password_hash VARCHAR(100) NOT NULL,
    role          VARCHAR(16)  NOT NULL,
    created_at    BIGINT       NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts           BIGINT       NOT NULL,
    client_key   VARCHAR(128) NOT NULL,
    ip           VARCHAR(64),
    method       VARCHAR(10),
    path         VARCHAR(512),
    status       INT,
    risk         INT,
    threat_level VARCHAR(16),
    action       VARCHAR(24)
);

CREATE TABLE IF NOT EXISTS client_blacklist (
    client_key    VARCHAR(128) NOT NULL PRIMARY KEY,
    blocked_until BIGINT       NOT NULL,
    offences      INT          NOT NULL,
    reason        VARCHAR(255)
);

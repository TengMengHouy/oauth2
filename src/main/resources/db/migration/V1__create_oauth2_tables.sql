-- V1__create_oauth2_tables.sql
-- NOTE: This is a trimmed version. For production use the official SQL from Spring Authorization Server.
CREATE TABLE oauth2_registered_client (
    id VARCHAR(100) PRIMARY KEY,
    client_id VARCHAR(100) UNIQUE NOT NULL,
    client_id_issued_at TIMESTAMP,
    client_secret VARCHAR(200),
    client_secret_expires_at TIMESTAMP,
    client_name VARCHAR(200),
    client_authentication_methods TEXT,
    authorization_grant_types TEXT,
    redirect_uris TEXT,
    scopes TEXT,
    client_settings TEXT,
    token_settings TEXT
);

CREATE TABLE oauth2_authorization (
    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100),
    principal_name VARCHAR(200),
    authorization_grant_type VARCHAR(100),
    attributes TEXT,
    state VARCHAR(500),
    authorization_code_value BYTEA,
    authorization_code_issued_at TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata TEXT,
    access_token_value BYTEA,
    access_token_issued_at TIMESTAMP,
    access_token_expires_at TIMESTAMP,
    access_token_metadata TEXT,
    access_token_jti VARCHAR(100),
    refresh_token_value BYTEA,
    refresh_token_issued_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    refresh_token_metadata TEXT,
    oidc_id_token_value BYTEA,
    oidc_id_token_issued_at TIMESTAMP,
    oidc_id_token_expires_at TIMESTAMP,
    oidc_id_token_metadata TEXT
);

CREATE TABLE oauth2_authorization_consent (
    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100),
    principal_name VARCHAR(200),
    authorities TEXT
);

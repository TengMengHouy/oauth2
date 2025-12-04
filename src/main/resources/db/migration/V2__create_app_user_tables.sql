-- V2__create_app_user_tables.sql
CREATE TABLE app_user (
    id BIGSERIAL PRIMARY KEY,
    uuid VARCHAR(36) UNIQUE,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(200),
    password VARCHAR(200) NOT NULL,
    family_name VARCHAR(200),
    given_name VARCHAR(200),
    phone_number VARCHAR(50),
    gender VARCHAR(20),
    dob DATE,
    profile_image TEXT,
    cover_image TEXT,
    account_non_expired BOOLEAN DEFAULT true,
    account_non_locked BOOLEAN DEFAULT true,
    credentials_non_expired BOOLEAN DEFAULT true,
    is_enabled BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false
);

CREATE TABLE authority (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE user_authority (
    user_id BIGINT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    authority_id BIGINT NOT NULL REFERENCES authority(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, authority_id)
);

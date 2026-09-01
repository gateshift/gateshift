-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Central device registry - MUST exist before any table that foreign-keys it
-- (fw_interfaces at 25, fw_routes at 26, fw_vrfs at 27, …). The application's
-- _ensure_devices_table() lifespan helper creates the same table with
-- CREATE TABLE IF NOT EXISTS, but that runs AFTER the MariaDB initdb phase -
-- so on a fresh install the FK-bearing init scripts would abort with
-- errno 150 (referenced table missing) and every script after them would be
-- skipped. Creating it here first makes the init sequence self-contained;
-- the app helper then no-ops. Schema mirrors the post-migration app state
-- (all ALTERs folded in) - keep the two in sync.
CREATE TABLE IF NOT EXISTS fw_devices (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    host_name        VARCHAR(255) NOT NULL UNIQUE COMMENT 'Matches device_host in logs',
    display_name     VARCHAR(255),
    platform         ENUM('panw','opnsense','fortigate','checkpoint','firepower','asa') NULL,
    role             ENUM('source','target','both') NOT NULL DEFAULT 'both',
    mgmt_ip          VARCHAR(255),
    mgmt_port        SMALLINT UNSIGNED DEFAULT 443,
    api_key          TEXT,
    gaia_user        VARCHAR(64)  NULL,
    gaia_password    TEXT         NULL,
    notes            TEXT,
    config           MEDIUMTEXT   NULL,
    software_version VARCHAR(64)  NULL,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

CREATE DATABASE IF NOT EXISTS gateshift
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- The MariaDB entrypoint creates the MARIADB_DATABASE before this file runs,
-- using the server's compiled-in default - which on 11.8 is
-- utf8mb4_uca1400_ai_ci. Force the database default back to unicode_ci so
-- every table created afterwards WITHOUT an explicit COLLATE (the app's
-- lifespan-created tables) inherits it and matches the schema files that pin
-- unicode_ci. Otherwise cross-collation JOINs fail with "Illegal mix of
-- collations".
ALTER DATABASE gateshift
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

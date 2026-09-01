-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_app_signatures (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_name VARCHAR(128) NOT NULL,
  proto ENUM('tcp','udp','sctp','dccp') NOT NULL,
  port_from SMALLINT UNSIGNED NOT NULL,
  port_to SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sig (proto, port_from, port_to),
  KEY idx_lookup (proto, port_from, port_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

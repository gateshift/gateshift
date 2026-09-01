-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_objects (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  obj_type ENUM(
    'ip','network','ip_group',
    'service','service_group',
    'application','application_group',
    'zone',
    'security_profile','security_profile_group'
  ) NOT NULL,

  name VARCHAR(255) NOT NULL,

  ip VARBINARY(16) NULL,
  ip_prefix TINYINT UNSIGNED NULL,

  proto VARCHAR(16) NULL,
  port_from SMALLINT UNSIGNED NULL,
  port_to SMALLINT UNSIGNED NULL,

  vendor VARCHAR(64) NULL,
  device_host VARCHAR(255) NULL,
  external_id VARCHAR(255) NULL,

  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uq_type_name (obj_type, name),
  UNIQUE KEY uq_ip (obj_type, ip, ip_prefix),
  UNIQUE KEY uq_service (obj_type, proto, port_from, port_to),
  UNIQUE KEY uq_ext (obj_type, vendor, device_host, external_id),

  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
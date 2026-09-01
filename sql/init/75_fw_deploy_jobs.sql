-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Async deploy-push jobs. Decouples the push work from the client HTTP
-- connection: POST /deploy/push starts a background worker and returns a
-- job_id; the work survives client disconnect, curl timeouts and browser
-- closes. The client observes progress via GET /deploy/push/{job_id}/stream
-- (SSE tail) or GET /deploy/push/{job_id} (snapshot).
--
-- status lifecycle:
--   running     - worker is iterating driver.push()
--   done        - worker finished; `success` holds the overall result
--   failed      - driver.push() raised (see error_text)
--   interrupted - process died mid-push (zombie-reaped at next startup)
--
-- session_handle holds the CP publish/discard handle ({sid, base_url}) once
-- the final push step stages a session; push_id links to it so the UI can
-- wire Publish/Discard. Replaces the former in-memory _PENDING_PUSHES dict -
-- one source of truth, survives a worker restart within the CP session TTL.
--
-- config is intentionally NOT stored: it is passed in-memory to the worker
-- (110 KB - 1.65 MB). A restart-interrupted push is re-initiated from the UI,
-- never auto-resumed - a half-applied vendor push cannot be safely continued.
CREATE TABLE IF NOT EXISTS fw_deploy_jobs (
  job_id         CHAR(32)                                          NOT NULL PRIMARY KEY,
  source_id      INT                                               NOT NULL,
  target_id      INT                                               NOT NULL,
  platform       VARCHAR(32)                                       NULL,
  strand         ENUM('policy','network')                          NOT NULL DEFAULT 'policy',
  status         ENUM('running','done','failed','interrupted')     NOT NULL DEFAULT 'running',
  success        TINYINT(1)                                        NULL,
  push_id        CHAR(32)                                          NULL,
  session_handle JSON                                              NULL,
  needs_commit   TINYINT(1)                                        NOT NULL DEFAULT 0,
  error_text     TEXT                                              NULL,
  created_at     TIMESTAMP                                         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP                                         NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                                     ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_target_status (target_id, status),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- One row per push step, appended as the worker emits PushResults. The stream
-- endpoint tails seq > Last-Event-ID; seq is per-job monotonic (assigned by
-- the worker). data_json carries optional extras (e.g. CP session_handle on
-- the staging step).
CREATE TABLE IF NOT EXISTS fw_deploy_job_events (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  job_id      CHAR(32)        NOT NULL,
  seq         INT             NOT NULL,
  step        VARCHAR(255)    NOT NULL,
  success     TINYINT(1)      NOT NULL DEFAULT 1,
  detail      TEXT            NULL,
  data_json   JSON            NULL,
  created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_job_seq (job_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Admission mutex: a SELECT ... FOR UPDATE on the target's row serializes the
-- check-running-then-insert decision so two concurrent POSTs to the same
-- target can't both start a push (which would collide into CP session-lock
-- hell). Rows are created lazily (INSERT IGNORE) on first push to a target.
CREATE TABLE IF NOT EXISTS fw_deploy_target_locks (
  target_id  INT        NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

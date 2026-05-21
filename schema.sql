-- ════════════════════════════════════════════════════════════════
--  PhishShield AI — Railway PostgreSQL Schema
--  Compatible with: Railway.app PostgreSQL plugin
--  Run via: Railway Dashboard → PostgreSQL → Query tab
--  OR via psql: psql $DATABASE_URL < railway_schema_postgresql.sql
-- ════════════════════════════════════════════════════════════════

-- Clean re-run (correct dependency order)
DROP TABLE IF EXISTS admin_reports;
DROP TABLE IF EXISTS scan_history;
DROP TABLE IF EXISTS users;

-- ── Users ─────────────────────────────────────────────────────────
CREATE TABLE users (
    id         SERIAL        NOT NULL,
    name       TEXT          NOT NULL DEFAULT '',
    username   VARCHAR(80)   NOT NULL,
    email      VARCHAR(120)  NOT NULL,
    password   VARCHAR(256)  NOT NULL,
    is_admin   SMALLINT      NOT NULL DEFAULT 0,
    created_at TIMESTAMP     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    CONSTRAINT uq_username UNIQUE (username),
    CONSTRAINT uq_email    UNIQUE (email)
);

-- ── Scan History ──────────────────────────────────────────────────
-- result      = 'safe' | 'warn' | 'phish'
-- is_phishing = 0 or 1  (boolean flag)
-- is_suspicious = 0 or 1
-- algo        = comma-separated model keys e.g. 'lr,rf,xgb,stack'
-- confidence  = 0.0 to 100.0
CREATE TABLE scan_history (
    id            SERIAL      NOT NULL,
    user_id       INTEGER     NOT NULL,
    url           TEXT        NOT NULL,
    result        VARCHAR(20) NOT NULL DEFAULT 'safe',
    confidence    REAL        NOT NULL DEFAULT 0,
    is_phishing   SMALLINT    NOT NULL DEFAULT 0,
    is_suspicious SMALLINT    NOT NULL DEFAULT 0,
    algo          TEXT        NOT NULL DEFAULT '',
    timestamp     TIMESTAMP   NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    CONSTRAINT fk_sh_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);

-- ── Admin Reports ─────────────────────────────────────────────────
CREATE TABLE admin_reports (
    id             SERIAL    NOT NULL,
    generated_by   INTEGER,
    generated_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    total_scans    INTEGER   NOT NULL DEFAULT 0,
    phishing_count INTEGER   NOT NULL DEFAULT 0,
    safe_count     INTEGER   NOT NULL DEFAULT 0,
    notes          TEXT,
    PRIMARY KEY (id),
    CONSTRAINT fk_ar_user
        FOREIGN KEY (generated_by) REFERENCES users(id)
        ON DELETE SET NULL
);

-- ── Indexes ───────────────────────────────────────────────────────
CREATE INDEX idx_scan_user      ON scan_history (user_id);
CREATE INDEX idx_scan_timestamp ON scan_history (timestamp DESC);
CREATE INDEX idx_scan_result    ON scan_history (result);
CREATE INDEX idx_scan_phishing  ON scan_history (is_phishing);

-- ════════════════════════════════════════════════════════════════
--  SEED DATA — Admin & Demo users
--  Passwords auto-set by app.py init_db() on first deploy
-- ════════════════════════════════════════════════════════════════

INSERT INTO users (name, username, email, password, is_admin) VALUES
('Admin', 'admin', 'admin@phishguard.ai',
 'pbkdf2:sha256:600000$placeholder$0000000000000000000000000000000000000000',
 1);

INSERT INTO users (name, username, email, password, is_admin) VALUES
('Demo User', 'demo', 'demo@phishguard.ai',
 'pbkdf2:sha256:600000$placeholder$0000000000000000000000000000000000000000',
 0);

-- ── Sample scan history (demo user id=2) ─────────────────────────
INSERT INTO scan_history
    (user_id, url, result, confidence, is_phishing, is_suspicious, algo, timestamp)
VALUES
(2,'https://www.google.com',                        'safe',  97.2,0,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '1 hour'),
(2,'http://paypa1-secure-login.tk/verify?user=you', 'phish', 94.5,1,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '2 hours'),
(2,'https://github.com/openai/whisper',             'safe',  96.8,0,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '3 hours'),
(2,'http://192.168.1.1/admin/login?redirect=bank',  'phish', 88.3,1,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '5 hours'),
(2,'https://www.amazon.com/orders',                 'safe',  91.0,0,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '1 day'),
(2,'http://bit.ly/3xK9mN2',                         'warn',  72.1,0,1,'xgb,lgb,rf,stack', NOW()-INTERVAL '2 days'),
(2,'https://stackoverflow.com/questions/12345',     'safe',  98.1,0,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '3 days'),
(2,'http://microsoft-support-update.xyz/fix',       'phish', 91.7,1,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '4 days'),
(2,'https://www.youtube.com/watch?v=dQw4w9WgXcQ',  'safe',  95.3,0,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '5 days'),
(2,'http://amaz0n-account-verify.ga/signin',        'phish', 96.2,1,0,'xgb,lgb,rf,stack', NOW()-INTERVAL '6 days');

-- ════════════════════════════════════════════════════════════════
--  VERIFY — Run this after to confirm success
-- ════════════════════════════════════════════════════════════════
SELECT 'users'         AS table_name, COUNT(*) AS rows FROM users
UNION ALL
SELECT 'scan_history'  AS table_name, COUNT(*) AS rows FROM scan_history
UNION ALL
SELECT 'admin_reports' AS table_name, COUNT(*) AS rows FROM admin_reports;

-- Full scan log check
SELECT
    u.name        AS user_name,
    s.url         AS url,
    s.result      AS verdict,
    s.confidence  AS confidence_pct,
    s.is_phishing AS phishing,
    s.algo        AS models_used,
    s.timestamp   AS scanned_at
FROM scan_history s
JOIN users u ON s.user_id = u.id
ORDER BY s.timestamp DESC;

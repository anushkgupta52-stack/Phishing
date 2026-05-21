-- ════════════════════════════════════════════════════════════════
--  PhishShield AI — schema.sql
--  Run once:  mysql -u root -p < schema.sql
-- ════════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS phishshield
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE phishshield;

-- Clean re-run
DROP TABLE IF EXISTS admin_reports;
DROP TABLE IF EXISTS scan_history;
DROP TABLE IF EXISTS users;

-- ── Users ────────────────────────────────────────────────────────
CREATE TABLE users (
    id         INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    username   VARCHAR(80)   NOT NULL,
    email      VARCHAR(120)  NOT NULL,
    password   VARCHAR(256)  NOT NULL,
    is_admin   TINYINT(1)    NOT NULL DEFAULT 0,
    created_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_username (username),
    UNIQUE KEY uq_email    (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Scan History ─────────────────────────────────────────────────
CREATE TABLE scan_history (
    id         INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    user_id    INT UNSIGNED  NOT NULL,
    url        TEXT          NOT NULL,
    result     ENUM('Phishing','Safe') NOT NULL,
    confidence FLOAT         NOT NULL DEFAULT 0,
    timestamp  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_user      (user_id),
    KEY idx_timestamp (timestamp),
    KEY idx_result    (result),
    CONSTRAINT fk_sh_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Admin Reports ─────────────────────────────────────────────────
CREATE TABLE admin_reports (
    id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    generated_by   INT UNSIGNED,
    generated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_scans    INT          NOT NULL DEFAULT 0,
    phishing_count INT          NOT NULL DEFAULT 0,
    safe_count     INT          NOT NULL DEFAULT 0,
    notes          TEXT,
    PRIMARY KEY (id),
    CONSTRAINT fk_ar_user
        FOREIGN KEY (generated_by) REFERENCES users(id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ════════════════════════════════════════════════════════════════
--  SEED DATA
-- ════════════════════════════════════════════════════════════════

-- Default admin  (password = Admin@1234)
-- ⚠ Replace hash below after running seed_admin.py
INSERT INTO users (username, email, password, is_admin) VALUES
('admin', 'admin@phishshield.io',
 'scrypt:32768:8:1$PLACEHOLDER$run_seed_admin_py_to_fix_this', 1);

-- Demo regular user  (password = User@1234)
INSERT INTO users (username, email, password, is_admin) VALUES
('demo', 'demo@phishshield.io',
 'scrypt:32768:8:1$PLACEHOLDER$run_seed_admin_py_to_fix_this', 0);

-- Sample scan history for demo user (id=2)
INSERT INTO scan_history (user_id, url, result, confidence, timestamp) VALUES
(2, 'https://www.google.com',                           'Safe',     97.2, NOW() - INTERVAL 1  HOUR),
(2, 'http://paypa1-secure-login.tk/verify?user=you',    'Phishing', 94.5, NOW() - INTERVAL 2  HOUR),
(2, 'https://github.com/openai/whisper',                'Safe',     96.8, NOW() - INTERVAL 3  HOUR),
(2, 'http://192.168.1.1/admin/login?redirect=bank',     'Phishing', 88.3, NOW() - INTERVAL 5  HOUR),
(2, 'https://www.amazon.com/orders',                    'Safe',     91.0, NOW() - INTERVAL 1  DAY),
(2, 'http://bit.ly/3xK9mN2',                            'Phishing', 72.1, NOW() - INTERVAL 2  DAY),
(2, 'https://stackoverflow.com/questions/12345',        'Safe',     98.1, NOW() - INTERVAL 3  DAY),
(2, 'http://microsoft-support-update.xyz/fix',          'Phishing', 91.7, NOW() - INTERVAL 4  DAY),
(2, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',     'Safe',     95.3, NOW() - INTERVAL 5  DAY),
(2, 'http://amaz0n-account-verify.ga/signin',           'Phishing', 96.2, NOW() - INTERVAL 6  DAY);

-- ════════════════════════════════════════════════════════════════
--  HOW TO SET REAL PASSWORDS
-- ════════════════════════════════════════════════════════════════
-- Run this in a Python shell once:
--
--   from werkzeug.security import generate_password_hash
--   print(generate_password_hash('Admin@1234'))
--   print(generate_password_hash('User@1234'))
--
-- Then:
--   UPDATE users SET password='<hash1>' WHERE username='admin';
--   UPDATE users SET password='<hash2>' WHERE username='demo';
--
-- OR use seed_admin.py (included).
-- ════════════════════════════════════════════════════════════════

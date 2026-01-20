-- =========================================================
-- CyberSec Insights Admin
-- Real App 1 - Insecure Baseline Database
-- Used for: CWE-89, CWE-79, CWE-601 demonstrations
-- =========================================================

-- -----------------------------
-- USERS TABLE
-- -----------------------------
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,      -- intentionally plaintext (insecure)
    role TEXT NOT NULL,          -- admin / user
    email TEXT,
    created_at TEXT
);

-- -----------------------------
-- POSTS TABLE
-- -----------------------------
DROP TABLE IF EXISTS posts;

CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,          -- stored XSS payload lives here
    author_id INTEGER NOT NULL,
    created_at TEXT,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

-- -----------------------------
-- SEED USERS
-- -----------------------------
INSERT INTO users (username, password, role, email, created_at) VALUES
('admin', 'admin123', 'admin', 'admin@cybersec.local', datetime('now')),
('alice', 'alice123', 'user',  'alice@cybersec.local', datetime('now')),
('bob',   'bob123',   'user',  'bob@cybersec.local',   datetime('now'));

-- -----------------------------
-- SEED POSTS
-- -----------------------------
INSERT INTO posts (title, body, author_id, created_at) VALUES
(
  'Welcome',
  'Welcome to CyberSec Insights Admin panel.',
  1,
  datetime('now')
),
(
  'Security Tip',
  'Never trust user input.',
  1,
  datetime('now')
);

